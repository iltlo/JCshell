#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_COMMANDS 30
#define MAX_COMMAND_LENGTH 1024
#define MAX_ARGS 30

// construct a struct to store the extracted fields
struct process_stat {
    int pid;
    char cmd[256];
    char state;
    int excode;
    char exsig[256];
    int ppid;
    unsigned long user;
    unsigned long sys;
    // double user;
    // double sys;
    unsigned long vctx;
    unsigned long nvctx;
    long long total_time;
    bool termBySig;
};

volatile sig_atomic_t sigusr1_received = 0;

void sigint_handler1(int signum) {
    printf("\n## JCshell [%d] ## ", getpid());
    // flush the stdout buffer
    fflush(stdout);
    // printf("\nJCshell: SIGINT (Ctrl-C) received.\n");
}
void sigusr1_handler(int signum) {
    sigusr1_received = 1;
}


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

struct process_stat get_process_statistics(pid_t pid, siginfo_t si) {
    // reference: https://man7.org/linux/man-pages/man5/proc.5.html
    
    struct process_stat process_info;

    char stat_filepath[256];
    char status_filepath[256];

    // Parse and extract fields from the stat line
    int extracted_pid;
    char cmd[256], state, exsig[256];  // exsig is the string representation of si.si_status
    int excode, ppid;
    unsigned long user, sys;
    long cutime, cstime;
    // double user, sys, cutime, cstime, start_time, total_time;
    unsigned long vctx, nvctx;
    unsigned long long start_time, total_time;

    // Construct the file paths for the stat and status files
    snprintf(stat_filepath, sizeof(stat_filepath), "/proc/%d/stat", pid);
    snprintf(status_filepath, sizeof(status_filepath), "/proc/%d/status", pid);


    FILE *stat_file = fopen(stat_filepath, "r");
    if (stat_file == NULL) {
        // report error
        fprintf(stderr, "JCshell: Error opening stat file\n");
        return process_info;
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
            // double user_ = atof(token) / sysconf(_SC_CLK_TCK);
        } else if (field == 15) {
            sys = atol(token);
            // sys = atof(token) / sysconf(_SC_CLK_TCK);
        } else if (field == 16) {
            cutime = atol(token);
            // cutime = atof(token) / sysconf(_SC_CLK_TCK);
        } else if (field == 17) {
            cstime = atol(token);
            // cstime = atof(token) / sysconf(_SC_CLK_TCK);
        } else if (field == 22) {
            start_time = atol(token);
            // start_time = atof(token) / sysconf(_SC_CLK_TCK);
        }
        token = strtok(NULL, " ");
        field++;
    }

    FILE *status_file = fopen(status_filepath, "r");
    if (status_file == NULL) {
        // report error
        fprintf(stderr, "JCshell: Error opening status file\n");
        return process_info;
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

    // total_time: termination time of the process
    total_time = start_time + user + sys + cutime + cstime;
    // printf("total_time: %lld, start_time: %lld, user: %lu, sys: %lu, cutime: %lu, cstime: %lu\n", total_time, start_time, user, sys, cutime, cstime);
    // printf("total_time: %f, start_time: %f, user: %f, sys: %f, cutime: %f, cstime: %f\n", total_time, start_time, user, sys, cutime, cstime);
    char * signal_name = strsignal(si.si_status);
    // store signal name in exsig
    strcpy(exsig, signal_name);

    // save the extracted fields to struct in oneline
    process_info = (struct process_stat){extracted_pid, " ", state, excode, " ", ppid, user, sys, vctx, nvctx, total_time, 0};
    strcpy(process_info.cmd, cmd);
    strcpy(process_info.exsig, exsig);

    return process_info;

}


void execute_job(char *commands[], int num_commands) {
    int pipefd[MAX_COMMANDS - 1][2];
    int num_pipefds = num_commands - 1;

    // printf("num_commands: %d\n", num_commands);

    // Create pipes for inter-process communication
    for (int i = 0; i < num_commands - 1; i++) {
        if (pipe(pipefd[i]) == -1) {
            fprintf(stderr, "JCshell: Failure creating pipe\n");
            exit(1);
        }
    }

    // Create an array to store child process PIDs
    pid_t child_pids[MAX_COMMANDS];

    // Fork child processes for each command
    for (int i = 0; i < num_commands; i++) {    // i: command index
        // printf("Ready to fork child process: %d\n", getpid());
        pid_t pid = fork();

        if (pid < 0) {
            fprintf(stderr, "JCshell: Error forking process\n");
            exit(1);
        } else if (pid == 0) {
            // Child process
            // printf("Child process: %d\n", getpid());

            sigset_t set;
            int sig;
            // Initialize a signal set containing SIGUSR1
            sigemptyset(&set);
            sigaddset(&set, SIGUSR1);
            // Block the signals in the set (prevent the signal from being delivered to the process)
            sigprocmask(SIG_BLOCK, &set, NULL);

            // Set the handler for SIGUSR1
            struct sigaction sa;
            sigaction(SIGUSR1, NULL, &sa);
            sa.sa_handler = sigusr1_handler;
            sigaction(SIGUSR1, &sa, NULL);

            // Wait for SIGUSR1 to be received
            // printf("Waiting for SIGUSR1...\n");
            if (sigwait(&set, &sig) == -1) {
                perror("sigwait");
                exit(EXIT_FAILURE);
            }

            // Install the SIGINT handler
            // struct sigaction sa;
            // sigaction(SIGINT, NULL, &sa);
            // sa.sa_handler = SIG_DFL;
            // sigaction(SIGINT, &sa, NULL);
            signal(SIGINT, SIG_DFL);


            for (int k = 0; k < num_pipefds; k++) { // k: pipefd index
                // Logic: remove all except pfd[i-1][0] (stdin), and pfd[i][1] (stdout)
                //          if i == 0, remove pfd[i-1][0] as well
                //          if i == num_pipefds, remove pfd[i][1] as well
                if (i == 0 && k == 0) {                                  // first
                    close(pipefd[k][0]);
                    dup2(pipefd[k][1], STDOUT_FILENO);
                } else if (i == num_commands-1 && k == num_pipefds-1) {  // last
                    close(pipefd[k][1]);
                    dup2(pipefd[k][0], STDIN_FILENO);
                } else {                                                 // middle
                    if (i-1 == k) {
                        close(pipefd[k][1]);
                        dup2(pipefd[k][0], STDIN_FILENO);
                    } else if (i == k) {
                        close(pipefd[k][0]);
                        dup2(pipefd[k][1], STDOUT_FILENO);
                    } else {
                        close(pipefd[k][0]);
                        close(pipefd[k][1]);
                    }
                }
            }
            
            // Print the command 
            // printf("Executing command: %s\n", commands[i]);
            // Execute the command
            execute_command(commands[i]);
        } else {
            // Parent process
            // printf("Parent process: %d\n", getpid());
            signal(SIGINT, SIG_IGN);
            child_pids[i] = pid;
        }
        // here, the parent process will continue to fork the next child process
    }

    // Send SIGUSR1 to wake up child processes when ready
    sleep(0.85);
    for (int i = 0; i < num_commands; i++) {
        // printf("Sending SIGUSR1 to child process %d\n", child_pids[i]);
        kill(child_pids[i], SIGUSR1);
    }

    // Close all pipes in the parent process
    for (int i = 0; i < num_commands - 1; i++) {
        close(pipefd[i][0]);
        close(pipefd[i][1]);
    }

    // Wait for all child processes to terminate
    siginfo_t si[num_commands];
    for (int i = 0; i < num_commands; i++) {
        waitid(P_PID, child_pids[i], &si[i], WNOWAIT | WEXITED);
    }

    // a struct array to store the stats
    struct process_stat stat_arr[num_commands];
    for (int i = 0; i < num_commands; i++) {
        stat_arr[i] = get_process_statistics(child_pids[i], si[i]);

        // Clear the zombie status and extract status and 
        int status;
        waitpid(child_pids[i], &status, 0);
        stat_arr[i].excode = WEXITSTATUS(status);   // (why doesn't match with /proc/<pid>/stat field 52?)
        if (WIFSIGNALED(status)){
            // printf("-----> Child process %d terminated by signal %d\n", child_pids[i], WTERMSIG(status));
            stat_arr[i].termBySig = true;
        } else { stat_arr[i].termBySig = false; }

    }

    // Sort stat_arr by total_time
    for (int j = 0; j < num_commands; j++) {
        for (int k = j+1; k < num_commands; k++) {
            if (stat_arr[j].total_time > stat_arr[k].total_time) {
                struct process_stat temp = stat_arr[j];
                stat_arr[j] = stat_arr[k];
                stat_arr[k] = temp;
            }
        }
    }   // bubble sort

    // print stats in termination order
    printf("\n");
    for (int i = 0; i < num_commands; i++) {
        if (stat_arr[i].termBySig) {    // process is terminated by signal
            // printf("(PID)%d (CMD)%s (STATE)%c (EXSIG)%s (PPID)%d (USER)%f (SYS)%f (VCTX)%lu (NVCTX)%lu\n", stat_arr[i].pid, stat_arr[i].cmd, stat_arr[i].state, stat_arr[i].exsig, stat_arr[i].ppid, stat_arr[i].user, stat_arr[i].sys, stat_arr[i].vctx, stat_arr[i].nvctx);
            printf("(PID)%d (CMD)%s (STATE)%c (EXSIG)%s (PPID)%d (USER)%lu (SYS)%lu (VCTX)%lu (NVCTX)%lu\n", stat_arr[i].pid, stat_arr[i].cmd, stat_arr[i].state, stat_arr[i].exsig, stat_arr[i].ppid, stat_arr[i].user, stat_arr[i].sys, stat_arr[i].vctx, stat_arr[i].nvctx);
        } else {
            // printf("(PID)%d (CMD)%s (STATE)%c (EXCODE)%d (PPID)%d (USER)%f (SYS)%f (VCTX)%lu (NVCTX)%lu\n", stat_arr[i].pid, stat_arr[i].cmd, stat_arr[i].state, stat_arr[i].excode, stat_arr[i].ppid, stat_arr[i].user, stat_arr[i].sys, stat_arr[i].vctx, stat_arr[i].nvctx);
            printf("(PID)%d (CMD)%s (STATE)%c (EXCODE)%d (PPID)%d (USER)%lu (SYS)%lu (VCTX)%lu (NVCTX)%lu\n", stat_arr[i].pid, stat_arr[i].cmd, stat_arr[i].state, stat_arr[i].excode, stat_arr[i].ppid, stat_arr[i].user, stat_arr[i].sys, stat_arr[i].vctx, stat_arr[i].nvctx);
        }
        // printf("(PID)%d (CMD)%s (STATE)%c (EXCODE)%d (EXSIG)%s (PPID)%d (USER)%lu (SYS)%lu (VCTX)%lu (NVCTX)%lu (Total_ime)%lld (termBySig)%d\n", stat_arr[i].pid, stat_arr[i].cmd, stat_arr[i].state, stat_arr[i].excode, stat_arr[i].exsig, stat_arr[i].ppid, stat_arr[i].user, stat_arr[i].sys, stat_arr[i].vctx, stat_arr[i].nvctx, stat_arr[i].total_time, stat_arr[i].termBySig);
    }
}

// Return error codes or messages:
// 0: Valid input
// 1: Empty input
// 2: Two consecutive pipes
// 3: Pipe at the beginning
// 4: Pipe at the end
int validate_input(const char *input) {
    if (strlen(input) == 0 || strspn(input, " ") == strlen(input)) {
        // if input is empty or only spaces
        return 1;
    } else if (strstr(input, "||") != NULL) {
        return 2;  // Two consecutive pipes
    } else if (input[0] == '|') {
        return 3;  // Pipe at the beginning
    } else if (input[strlen(input) - 1] == '|') {
        return 4;  // Pipe at the end
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

    // Install the SIGINT handler
    // struct sigaction sa;
    // sigaction(SIGINT, NULL, &sa);
    // sa.sa_handler = sigint_handler1;
    // sigaction(SIGINT, &sa, NULL);

    while (1) {
        signal(SIGINT, sigint_handler1);

        // Print shell prompt with process ID
        printf("## JCshell [%d] ## ", getpid());

        // Read user input
        fgets(input, sizeof(input), stdin);
        // flush the stdin buffer
        fflush(stdin);

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
            // fprintf(stderr, "JCshell: should not have empty input\n");
            continue;
        } else if (error_code == 2) {
            fprintf(stderr, "JCshell: should not have two | symbols without in-between command\n");
            continue;
        } else if (error_code == 3) {
            fprintf(stderr, "JCshell: should not have a | symbol at the beginning of the command\n");
            continue;
        } else if (error_code == 4) {
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

