#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define BLK "\x1b[30m"
#define RED "\x1b[31m"
#define GRN "\x1b[32m"
#define YEL "\x1b[33m"
#define BLU "\x1b[34m"
#define MAG "\x1b[35m"
#define CYN "\x1b[36m"
#define WHT "\x1b[37m"

#define RST "\x1b[0m"

#define SPACE_DELIM "\f\n\r\t\v "

#define MAX_PIPELINE_SIZE 64
#define MAX_JOBS 64


typedef struct Command
{
    char *name;
    char **args;
    pid_t pid;
} Command;

typedef struct Pipeline
{
    Command **commands;
    int len;
    int maxLen;
    char *inputFile;
    char *outputFile;
    bool background;
} Pipeline;

typedef void (*BuiltinHandler)(Command *command);

typedef struct {
    const char *name;
    BuiltinHandler handler;
} BuiltinMap;

void *uMalloc(size_t size)
{
    void *ptr = malloc(size);

    if (ptr == NULL)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    return ptr;
}

void *uRealloc(void *ptr, size_t size)
{
    void *newPtr = realloc(ptr, size);

    if (ptr == NULL && size != 0)
    {
        perror("realloc");
        exit(EXIT_FAILURE);
    }

    return newPtr;
}

int uFork()
{
    int pid = fork();

    if (pid == -1)
    {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    return pid;
}

int uPipe(int *pipedes) {
    if (pipe(pipedes) == -1)
    {
        perror("pipe");
        exit(EXIT_FAILURE);
    }
}

char *uGetCwd()
{
    char *cwd = NULL;

    if ((cwd = getcwd(NULL, 0)) == NULL)
    {
        perror("Failed to get current working directory\n");
        exit(EXIT_FAILURE);
    }

    return cwd;
}

char *uGetLogin(size_t len)
{
    size_t size = len * sizeof(char);
    char *name = (char *)uMalloc(size);

    errno = 0;
    struct passwd *pw = getpwuid(getuid());

    if (pw == NULL)
    {
        strncpy(name, "(?)", size - 1);
    }
    else
    {
        stpncpy(name, pw->pw_name, size);
    }

    name[len - 1] = '\0';

    return name;
}

char *uGetHostname(size_t len)
{
    size_t size = len * sizeof(char);
    char *name = (char *)uMalloc(size);

    if (gethostname(name, size) == -1)
    {
        if (errno == ENAMETOOLONG)
        {
            name[len - 1] = '\0';
        }
        else
        {
            strncpy(name, "(?)", size - 1);
        }
    }

    return name;
}

void cmdExit(Command *command) {
    exit(EXIT_SUCCESS);
}

void cmdCd(Command *command) {
    char *targetDir = command->args[1];

    if (targetDir == NULL) {
        targetDir = getenv("HOME");
    }

    if (chdir(targetDir) != 0) {
        perror("cd");
    } else {
        char *cwd = NULL;
        if ((cwd = getcwd(cwd, 0)) != NULL) {
            setenv("PWD", cwd, 1);
        }
        free(cwd);
    }
}

void prompt()
{
    char *login = uGetLogin(64);
    char *hostname = uGetHostname(64);
    char *cwd = uGetCwd();

    fprintf(stdout, GRN "%s@%s" RST ":" BLU "%s" RST "$ ", login, hostname,
            cwd);
    fflush(stdout);

    free(login);
    free(hostname);
    free(cwd);
}

char *readLine()
{
    char *buf = NULL;
    size_t bufSize = 0;

    prompt();

    if (getline(&buf, &bufSize, stdin) == -1)
    {
        free(buf);
        buf = NULL;

        if (feof(stdin))
        {
            cmdExit(NULL);
        }
        else
        {
            perror("Failed to get line");
            exit(EXIT_FAILURE);
        }
    }

    return buf;
}

char **splitString(char *str, char *delim)
{
    unsigned int len = BUFSIZ;
    char **tokens = uMalloc(len * sizeof(*tokens));

    unsigned int pos = 0;

    for (char *token = strtok(str, delim); token; token = strtok(NULL, delim))
    {
        if (pos >= len)
        {
            len *= 2;
            tokens = uRealloc(tokens, len * sizeof(*tokens));
        }

        tokens[pos++] = token;
    }

    tokens[pos] = NULL;

    return tokens;
}

Command *createCommand()
{
    Command *newCommand = (Command *)uMalloc(sizeof(Command));
    newCommand->name = NULL;
    newCommand->args = NULL;
    newCommand->pid = 0;
    return newCommand;
}

Pipeline *createPipeline(size_t maxLen)
{
    Pipeline *newPipeline = (Pipeline *)uMalloc(sizeof(Pipeline));

    newPipeline->commands = (Command **)uMalloc(maxLen * sizeof(Command *));

    for (size_t i = 0; i < maxLen; i++)
    {
        newPipeline->commands[i] = NULL;
    }

    newPipeline->len = 0;
    newPipeline->maxLen = maxLen;
    newPipeline->inputFile = NULL;
    newPipeline->outputFile = NULL;
    newPipeline->background = false;
    return newPipeline;
}

void freeCommand(Command *command)
{
    if (command == NULL)
    {
        return;
    }
    free(command->args);
    free(command);
}

void freePipeline(Pipeline *pipeline)
{
    if (pipeline == NULL)
    {
        return;
    }

    for (int i = 0; i < pipeline->len; i++)
    {
        freeCommand(pipeline->commands[i]);
    }

    free(pipeline->commands);
    free(pipeline);
}

Pipeline *parseLine(char *line)
{
    // Ex: cat < ush.c | grep int | wc > output.txt &

    Pipeline *pipeline = createPipeline(MAX_PIPELINE_SIZE);
    pipeline->len = 0;

    char *newLine = strchr(line, '\n');
    if (newLine) {
        *newLine = '\0';
    }

    char *bgOp = strchr(line, '&');
    if (bgOp)
    {
        pipeline->background = true;
        *bgOp = '\0';
    }

    char *outputRedirectOp = strchr(line, '>');
    if (outputRedirectOp)
    {
        *outputRedirectOp = '\0';
        pipeline->outputFile = strtok(outputRedirectOp + 1, SPACE_DELIM);
    }

    char **pipedStrs = splitString(line, "|");
    for (int i = 0; pipedStrs[i] != NULL; i++)
    {
        if (i >= pipeline->maxLen)
        {
            puts(RED "Max pipeline size reached" RST);
            freePipeline(pipeline);
            free(pipedStrs);
            exit(EXIT_FAILURE);
        }

        pipeline->commands[i] = createCommand();

        if (i == 0)
        {
            char *inputRedirectOp = strchr(pipedStrs[i], '<');
            if (inputRedirectOp)
            {
                *inputRedirectOp = '\0';
                pipeline->inputFile = strtok(inputRedirectOp + 1, SPACE_DELIM);
            }
        }

        char **cmdArgs = splitString(pipedStrs[i], SPACE_DELIM);
        pipeline->commands[i]->name = cmdArgs[0];
        pipeline->commands[i]->args = cmdArgs;
        pipeline->len++;
    }

    free(pipedStrs);
    return pipeline;
}

void setInputRedirect(char *inputFile)
{
    int inputFileFd = open(inputFile, O_RDONLY);
    if (inputFileFd == -1)
    {
        perror("input file");
        exit(EXIT_FAILURE);
    }
    dup2(inputFileFd, STDIN_FILENO);
    close(inputFileFd);
}

void setOutputRedirect(char *outputFile)
{
    int outputFileFd = open(outputFile, O_WRONLY | O_CREAT | O_TRUNC, 0664);

    if (outputFileFd == -1)
    {
        perror("output file");
        exit(EXIT_FAILURE);
    }

    dup2(outputFileFd, STDOUT_FILENO);
    close(outputFileFd);
}

void setPipelineInput(int inputFd)
{
    dup2(inputFd, STDIN_FILENO);
    close(inputFd);
}

void setPipelineOutput(int pipeFds[])
{
    dup2(pipeFds[1], STDOUT_FILENO);
    close(pipeFds[0]);
    close(pipeFds[1]);
}

void printNewBackgroundJob(Pipeline *pipeline) {
    if (!pipeline->background) return;

    for (int i = 0; i < pipeline->len; i++)
    {
        printf(YEL "[+process]:\t" RST);
        printf(MAG "%d\n" RST, pipeline->commands[i]->pid);
    }
    
    printf(RST "\n");
}

void waitPipeline(Pipeline *pipeline) {
    for (int i = 0; i < pipeline->len; i++)
    {
        waitpid(pipeline->commands[i]->pid, NULL, 0);
    }
}

void reapChildren() {
    pid_t pid;
    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
        printf(YEL "[+process terminated]:\t" RST);
        printf(MAG "%d\n" RST, pid);
    }
}

void executePipeline(Pipeline *pipeline)
{
    if (pipeline->len == 0) return;

    int pipefds[2];
    int inputFd = STDIN_FILENO;

    const size_t firstIndex = 0;
    const size_t lastIndex = pipeline->len - 1;

    for (int i = 0; i < pipeline->len; i++)
    {
        Command *cmd = pipeline->commands[i];

        if (i < lastIndex)
            uPipe(pipefds);

        cmd->pid = uFork();

        if (cmd->pid == 0) /* Child process */
        {
            if (i == firstIndex && pipeline->inputFile)
                setInputRedirect(pipeline->inputFile);
            else if (inputFd != STDIN_FILENO)
                setPipelineInput(inputFd);

            if (i == lastIndex && pipeline->outputFile)
                setOutputRedirect(pipeline->outputFile);
            else if (i < lastIndex)
                setPipelineOutput(pipefds);

            if (execvp(cmd->name, cmd->args) == -1)
            {
                fprintf(stderr, "ush: could not execute command: %s\n", cmd->name);
                exit(EXIT_FAILURE);
            }
        }
        else /* Parent process */
        {
            if (inputFd != STDIN_FILENO)
            {
                close(inputFd);
            }

            if (i < lastIndex)
            {
                inputFd = pipefds[0];
                close(pipefds[1]);
            }
        }
    }

    if (pipeline->background)
        printNewBackgroundJob(pipeline);
    else
        waitPipeline(pipeline);
}

BuiltinMap builtinTable[] = {
    { "exit", cmdExit },
    { "cd" , cmdCd },
    { NULL, NULL }
};

BuiltinHandler findBuiltinHandler(const char *input) {
    for (int i = 0; builtinTable[i].name != NULL; i++) {
        if (strcmp(input, builtinTable[i].name) == 0) {
            return builtinTable[i].handler;
        }
    }
    return NULL;
}

void execute(Pipeline *pipeline) {
    for (int i = 0; i < pipeline->len; i++) {
        BuiltinHandler handler = findBuiltinHandler(pipeline->commands[i]->name);
        if (handler) {
            handler(pipeline->commands[i]);
            return;
        }
    }

    executePipeline(pipeline);
}

int main()
{
    while (1)
    {
        reapChildren();

        char *line = readLine();

        if (line == NULL) continue;

        Pipeline *pipeline = parseLine(line);
        execute(pipeline);

        freePipeline(pipeline);
        free(line);
    }

    return EXIT_SUCCESS;
}
