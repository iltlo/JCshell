#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#define MAX_COMMANDS 30
#define MAX_COMMAND_LENGTH 1024
#define MAX_ARGS 30

void execute_command(char *command) {
    char *args[MAX_ARGS];
    int arg_count = 0;

    // Tokenize the command into arguments
    char *token = strtok(command, " ");
    while (token != NULL) {
        args[arg_count++] = token;
        token = strtok(NULL, " ");
    }
    args[arg_count] = NULL;

    // Execute the command
    if (execvp(args[0], args) == -1){
        fprintf(stderr, "JCshell: '%s': ", args[0]);
        perror("");
    }

    // If execvp returns (isnt replaced by the args[0] command), there was an error
    exit(1);
}

void execute_job(char *commands[], int num_commands) {
    int pipefd[MAX_COMMANDS - 1][2];

    // printf("num_commands: %d\n", num_commands);

    // Create pipes for inter-process communication
    for (int i = 0; i < num_commands - 1; i++) {
        if (pipe(pipefd[i]) == -1) {
            perror("Failure creating pipe");
            exit(1);
        }
    }

    // Fork child processes for each command
    for (int i = 0; i < num_commands; i++) {
        // printf("Ready to fork child process: %d\n", getpid());
        pid_t pid = fork();

        if (pid < 0) {
            perror("Error forking process");
            exit(1);
        } else if (pid == 0) {
            // printf("Child process: %d\n", getpid());
            // Child process

            // Redirect input from previous command (if not the first command)
            if (i > 0) {
                close(pipefd[i - 1][1]);
                dup2(pipefd[i - 1][0], STDIN_FILENO);
            }
            else { // (i == 0)
                // close all pipefds except pipefd[0][1]
                for (int j = 1; j < num_commands - 1; j++) {
                    close(pipefd[j][0]);
                    close(pipefd[j][1]);
                }
            }
            // Redirect output to next command (if not the last command)
            if (i < num_commands - 1) {
                close(pipefd[i][0]);
                dup2(pipefd[i][1], STDOUT_FILENO);
            } else { // last command
                // close all pipefds except pipefd[i][0]
                for (int j = 0; j < num_commands - 2; j++) {
                    close(pipefd[j][0]);
                    close(pipefd[j][1]);
                }
            }
            
            // Execute the command
            execute_command(commands[i]);
        } else {
            // Parent process
            // printf("Parent process: %d\n", getpid());
        }
    }

    // Close all pipes in the parent process
    for (int i = 0; i < num_commands - 1; i++) {
        close(pipefd[i][0]);
        close(pipefd[i][1]);
    }

    // Wait for all child processes to terminate
    for (int i = 0; i < num_commands; i++) {
        wait(NULL);
    }
}

// utility funcitons
void print_cmds(char * arr[], int size) {
    printf("Printing `commands`-> ");
    for (int i = 0; i < size; i++) {
        printf("%d: %s",i , (char*)arr[i]);
    }
    printf("\n");
}

int main() {
    char input[MAX_COMMAND_LENGTH];

    while (1) {
        // Print shell prompt with process ID
        printf("## JCshell [%d] ## ", getpid());

        // Read user input
        if (fgets(input, sizeof(input), stdin) == NULL) {
            // End of input (e.g., EOF or error)
            break;
        }

        // Convert trailing newline character to NULL character
        int input_length = (int)strcspn(input, "\n");
        // printf("input_length: %d\n", input_length);
        input[input_length] = '\0';

        // Check if the user wants to exit
        if (strcmp(input, "exit") == 0) {
            break;
        }

        // Tokenize the input into commands separated by pipes
        char *commands[MAX_COMMANDS];       // array of commands 
        int num_commands = 0;

        char *token = strtok(input, "|");   // returns the pointer to the first token encountered in the string
        // printf("token: %s\n", token);
        while (token != NULL) {
            // printf("Command: %s\n", token);
            commands[num_commands++] = token;
            token = strtok(NULL, "|");
        }

        // print_cmds(commands, num_commands);

        // Execute the job
        execute_job(commands, num_commands);
    }

    return 0;
}

