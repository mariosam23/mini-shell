// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1
#define ERROR		-1
#define SUCCESS		0
#define HOME "HOME"

static int execute_cd(simple_command_t *s, char **verb);
static int execute_exit(char **verb);
static int variable_assignment(simple_command_t *s, char **verb);
static int open_file(const char *filename, int io_flags, int append_flag);
static void free_pointers(void *first, ...);

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	char *path = dir ? (char *)dir->string : getenv(HOME);

	DIE(!path, "error getting path");

	int res = chdir(path);

	if (dir)
		free(path);

	return res == 0;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	return SHELL_EXIT;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* Sanity checks. */
	if (!s)
		return ERROR;

	/* If builtin command, execute the command. */

	char *verb = get_word(s->verb);

	if (strcmp(verb, "cd") == 0)
		return execute_cd(s, &verb);
	else if (strcmp(verb, "exit") == 0 || strcmp(verb, "quit") == 0)
		return execute_exit(&verb);
	else if (strchr(verb, '='))
		return variable_assignment(s, &verb);

	/* If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */

	int pid = fork();

	DIE(pid < 0, "fork()\n");

	if (pid) {
		int status;

		int res = waitpid(pid, &status, 0);

		DIE(!res, "Error\n");

		free(verb);

		if (WIFEXITED(status))
			return WEXITSTATUS(status);

		return SUCCESS;
	}

	int size;

	char **argv = get_argv(s, &size);


	if (s->in) {
		char *in = get_word(s->in);
		int fd = open(in, O_RDONLY);

		DIE(fd < 0, "open()\n");

		dup2(fd, STDIN_FILENO);
		close(fd);
		free(in);
	}

	if (s->out && s->err) {
		char *out = get_word(s->out);
		char *err = get_word(s->err);

		if (!strcmp(out, err)) {
			int fd = open_file(out, s->io_flags, IO_OUT_APPEND);

			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);

			close(fd);
			free_pointers(out, err, NULL);
		} else {
			int fd_out = open_file(out, s->io_flags, IO_OUT_APPEND);

			dup2(fd_out, STDOUT_FILENO);
			close(fd_out);

			int fd_err = open_file(err, s->io_flags, IO_ERR_APPEND);

			dup2(fd_err, STDERR_FILENO);
			close(fd_err);
			free_pointers(out, err, NULL);
		}
	} else if (s->out) {
		char *out = get_word(s->out);

		int fd_out = open_file(out, s->io_flags, IO_OUT_APPEND);

		dup2(fd_out, STDOUT_FILENO);
		free(out);
	} else if (s->err) {
		char *err = get_word(s->err);

		int fd_err = open_file(err, s->io_flags, IO_ERR_APPEND);

		dup2(fd_err, STDERR_FILENO);
		close(fd_err);
		free(err);
	}

	int res = execvp(verb, argv);

	if (res) {
		printf("Execution failed for '%s'\n", verb);
		free(verb);
		exit(ERROR);
	}

	for (size_t i = 0; i < (size_t)size; ++i)
		free(argv[i]);

	free_pointers(argv, verb, NULL);

	exit(SUCCESS);
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* Execute cmd1 and cmd2 simultaneously. */
	int pid1 = fork();

	DIE(pid1 < 0, "fork()\n");

	if (pid1 == 0) { /* if in child process */
		int res = parse_command(cmd1, level + 1, cmd1->up);

		exit(res);
	}

	int pid2 = fork();

	DIE(pid2 < 0, "fork()\n");

	if (pid2 == 0) { /* if in child process */
		int res = parse_command(cmd2, level + 1, cmd2->up);

		exit(res);
	}

	int status1;
	int status2;

	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	return (status1 || status2 ? true : false);
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
						command_t *father)
{
	/* Redirect the output of cmd1 to the input of cmd2. */
	int fd[2];

	if (pipe(fd) < 0)
		return false;

	int pid1 = fork();

	DIE(pid1 < 0, "fork()\n");

	if (pid1 == 0) { /* In child process */
		close(fd[READ]);
		dup2(fd[WRITE], STDOUT_FILENO);
		close(fd[WRITE]);

		int res = parse_command(cmd1, level + 1, cmd1->up);

		exit(res);
	}

	int pid2 = fork();

	DIE(pid2 < 0, "fork()\n");

	if (pid2 == 0) { /* In child process */
		close(fd[WRITE]);
		dup2(fd[READ], STDIN_FILENO);
		close(fd[READ]);

		int res = parse_command(cmd2, level + 1, cmd2->up);

		exit(res);
	}

	close(fd[READ]);
	close(fd[WRITE]);

	int status1;
	int status2;

	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	if (WIFEXITED(status1) && WIFEXITED(status2))
		return (WEXITSTATUS(status2));

	return true;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* sanity checks */
	if (!c)
		return ERROR;

	int res = 0;

	switch (c->op) {
	case OP_NONE:
		res = parse_simple(c->scmd, level + 1, c);
		break;
	case OP_SEQUENTIAL:
		/* Execute the commands one after the other. */
		parse_command(c->cmd1, level + 1, c);
		if (res != SHELL_EXIT)
			res = parse_command(c->cmd2, level + 1, c);

		break;

	case OP_PARALLEL:
		/* Execute the commands simultaneously. */
		res = (int)run_in_parallel(c->cmd1, c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_NZERO:
		/* Execute the second command only if the first one
		 * returns non zero.
		 */
		res = parse_command(c->cmd1, level + 1, c);
		if (res)
			res = parse_command(c->cmd2, level + 1, c);

		break;

	case OP_CONDITIONAL_ZERO:
		/* Execute the second command only if the first one
		 * returns zero.
		 */
		res = parse_command(c->cmd1, level + 1, c);
		if (!res)
			res = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PIPE:
		/* Redirect the output of the first command to the
		 * input of the second.
		 */
		res = (int)run_on_pipe(c->cmd1, c->cmd2, level + 1, c);
		break;

	default:
		return SHELL_EXIT;
	}

	return res;
}

static int execute_cd(simple_command_t *s, char **verb)
{
	if (s->out) {
		char *out = (char *)s->out->string;
		int fd = open(out, O_WRONLY | O_TRUNC | O_CREAT, 0644);

		free(out);
		close(fd);
	}

	if (s->err) {
		char *err = (char *)s->err->string;
		int fd = open(err, O_WRONLY | O_TRUNC | O_CREAT, 0644);

		free(err);
		close(fd);
	}

	free(verb);

	return shell_cd(s->params) ? SUCCESS : ERROR;
}

static int execute_exit(char **verb)
{
	free(verb);
	return shell_exit();
}

/* Function to assign a value to an environment variable */
static int variable_assignment(simple_command_t *s, char **verb)
{
	const char *name = s->verb->string;
	char *value = get_word(s->verb->next_part->next_part);

	char *name_value = calloc(strlen(name) + strlen(value) + 2, sizeof(char));

	strcat(name_value, name);
	strcat(name_value, "=");
	strcat(name_value, value);

	int res = putenv(name_value);

	free_pointers(verb, value, name_value, NULL);

	return res;
}

/* Function to open a file with the appropriate flags */
static int open_file(const char *filename, int io_flags, int append_flag)
{
	int flags = O_WRONLY | O_CREAT;

	if (append_flag == IO_ERR_APPEND)
		flags |= (io_flags & IO_ERR_APPEND) ? O_APPEND : O_TRUNC;
	else if (append_flag == IO_OUT_APPEND)
		flags |= (io_flags & IO_OUT_APPEND) ? O_APPEND : O_TRUNC;

	int fd = open(filename, flags, 0644);

	DIE(fd < 0, "open()\n");
	return fd;
}

/* Free multiple pointers. The last value should be NULL */
static void free_pointers(void *first, ...)
{
	va_list args;

	va_start(args, first);

	void *pointer = first;

	while (pointer) {
		free(pointer);
		pointer = va_arg(args, void *);
	}

	va_end(args);
}
