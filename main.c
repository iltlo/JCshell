#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
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

void print_process_statistics(pid_t pid) {
    // reference: https://man7.org/linux/man-pages/man5/proc.5.html

    char stat_filepath[256];
    char status_filepath[256];

    // Parse and extract fields from the stat line
    int extracted_pid;
    char cmd[256], state;
    int excode, exsig, ppid;
    unsigned long user, sys;
    unsigned long vctx, nvctx;

    // Construct the file paths for the stat and status files
    snprintf(stat_filepath, sizeof(stat_filepath), "/proc/%d/stat", pid);
    snprintf(status_filepath, sizeof(status_filepath), "/proc/%d/status", pid);


    FILE *stat_file = fopen(stat_filepath, "r");
    if (stat_file == NULL) {
        // report error
        fprintf(stderr, "JCshell: Error opening stat file\n");
        return;
    }
    // Read and print process statistics
    char stat_line[2048];  // Adjust buffer size as needed
    if (fgets(stat_line, sizeof(stat_line), stat_file) == NULL) {
        // report error
        printf("errno: %d\n", errno);
        fprintf(stderr, "JCshell: Error reading from stat file\n");
        fclose(stat_file);
    }
    fclose(stat_file);
    // Tokenize the line
    char *token = strtok(stat_line, " ");
    int field = 1;
    // Extract the fields from the stat line
    while (token != NULL) {
        if (field == 1) {
            extracted_pid = atoi(token);
        } else if (field == 2) {
            // remove the brackets and save to cmd
            char *cmd_ptr = token;
            cmd_ptr++;
            cmd_ptr[strlen(cmd_ptr) - 1] = '\0';
            strcpy(cmd, cmd_ptr);
        } else if (field == 3) {
            state = token[0];
        } else if (field == 52) {
            excode = atoi(token);
        } else if (field == 14) {
            user = atol(token);
        } else if (field == 15) {
            sys = atol(token);
        } 
        token = strtok(NULL, " ");
        field++;
    }

    FILE *status_file = fopen(status_filepath, "r");
    if (status_file == NULL) {
        // report error
        fprintf(stderr, "JCshell: Error opening status file\n");
        return;
    }
    // Read and print process statistics
    char status_line[2048];  // Adjust buffer size as needed
    while (fgets(status_line, sizeof(status_line), status_file) != NULL) {
        // Extract the fields from the status line
        if (strstr(status_line, "PPid:") != NULL) {
            char *ppid_ptr = status_line;
            ppid_ptr += 6;
            ppid = atoi(ppid_ptr);
        } else if (strstr(status_line, "nonvoluntary_ctxt_switches:") != NULL) {
            // printf("2-> %s", status_line);
            char *nvctx_ptr = status_line;
            // traverse until seeing a digit
            while (*nvctx_ptr < '0' || *nvctx_ptr > '9') {
                nvctx_ptr++;
            }
            nvctx = atol(nvctx_ptr);
        } else if (strstr(status_line, "voluntary_ctxt_switches:") != NULL) {
            // printf("3-> %s", status_line);
            char *vctx_ptr = status_line;
            // traverse until seeing a digit
            while (*vctx_ptr < '0' || *vctx_ptr > '9') {
                vctx_ptr++;
            }
            vctx = atol(vctx_ptr);
        }
        // note that reverting the order of the if statements will cause incorrect output
    }

    sscanf(stat_line, "%d %s %c %d %d %d %lu %lu %*d %*d %lu %lu",
           &extracted_pid, cmd, &state, &excode, &exsig, &ppid, &user, &sys, &vctx, &nvctx);

    // Print the extracted fields in the specified format
    printf("(PID)%d (CMD)%s (STATE)%c (EXCODE)%d (EXSIG)%d (PPID)%d (USER)%.2f (SYS)%.2f (VCTX)%lu (NVCTX)%lu\n",
           extracted_pid, cmd, state, excode, exsig, ppid,
           (double)user / sysconf(_SC_CLK_TCK), (double)sys / sysconf(_SC_CLK_TCK), vctx, nvctx);
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

    // Create an array to store child process PIDs
    pid_t child_pids[MAX_COMMANDS];
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
            child_pids[i] = pid;
        }
    }

    // Close all pipes in the parent process
    for (int i = 0; i < num_commands - 1; i++) {
        close(pipefd[i][0]);
        close(pipefd[i][1]);
    }

    // Wait for all child processes to terminate and print their statistics
    // TODO: fix print stat after all child terminates
    for (int i = 0; i < num_commands; i++) {
        siginfo_t si;
        // waitid(P_PID, child_pids[i], &si, WNOWAIT | WEXITED);
        waitid(P_PID, child_pids[i], &si, WNOWAIT | WEXITED);

        print_process_statistics(child_pids[i]);
        // Extract terminating signal name
        char * signal_name = strsignal(si.si_status);
        printf("(SIGNAL)%s\n", signal_name);
        
        // Clear the zombie status
        waitpid(child_pids[i], NULL, 0);
    }
}

// Return error codes or messages:
// 0: Valid input
// 1: Two consecutive pipes
// 2: Pipe at the beginning
// 3: Pipe at the end
int validate_input(const char *input) {
    if (strstr(input, "||") != NULL) {
        return 1;  // Two consecutive pipes
    } else if (input[0] == '|') {
        return 2;  // Pipe at the beginning
    } else if (input[strlen(input) - 1] == '|') {
        return 3;  // Pipe at the end
    }
    return 0;  // Valid input
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
        input[input_length] = '\0';

        // make a copy for input (to facilitate tokenization)
        char input_copy[MAX_COMMAND_LENGTH];
        strcpy(input_copy, input);
        // Tokenize the input by space
        char* token = strtok(input_copy, " ");  // returns the pointer to the first token encountered in the string
        // Check if the user wants to exit
        if (token != NULL && strcmp(token, "exit") == 0) {
            // Check for additional arguments from input
            token = strtok(NULL, " ");
            if (token != NULL) {
                // User entered "exit" with additional arguments
                fprintf(stderr, "JCshell: 'exit' with other arguments!!!\n");
                continue;
            } else {
                // User only entered "exit"
                break;
            }
        }

        // Validate input for consecutive pipes and pipes at the beginning or end
        int error_code = validate_input(input);
        if (error_code == 1) {
            fprintf(stderr, "JCshell: should not have two | symbols without in-between command\n");
            continue;
        } else if (error_code == 2) {
            fprintf(stderr, "JCshell: should not have a | symbol at the beginning of the command\n");
            continue;
        } else if (error_code == 3) {
            fprintf(stderr, "JCshell: should not have a | symbol at the end of the command\n");
            continue;
        }

        // Tokenize the input into commands separated by pipes
        char *commands[MAX_COMMANDS];       // array of commands 
        int num_commands = 0;

        token = strtok(input, "|");
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

