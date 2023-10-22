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

void extract_stat(int num_commands, pid_t child_pids[], siginfo_t si[]);

// struct to store the process stat extracted fields
typedef struct ProcessStat {
    int pid;
    char cmd[256];
    char state;
    int excode;
    char exsig[256];
    int ppid;
    double user;
    double sys;
    unsigned long vctx;
    unsigned long nvctx;
    double total_time;
    bool termBySig;
} ProcessStat;

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

ProcessStat get_process_stat(pid_t pid, siginfo_t si) {
    // reference: https://man7.org/linux/man-pages/man5/proc.5.html
    
    ProcessStat process_info;

    char stat_filepath[256];
    char status_filepath[256];

    // Parse and extract fields from the stat line
    int extracted_pid;
    char cmd[256], state, exsig[256];  // exsig is the string representation of si.si_status
    int excode, ppid;
    double user, sys, cutime, cstime, start_time, total_time;
    unsigned long vctx, nvctx;

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
            user = atof(token) / sysconf(_SC_CLK_TCK);
        } else if (field == 15) {
            sys = atof(token) / sysconf(_SC_CLK_TCK);
        } else if (field == 16) {
            cutime = atof(token) / sysconf(_SC_CLK_TCK);
        } else if (field == 17) {
            cstime = atof(token) / sysconf(_SC_CLK_TCK);
        } else if (field == 22) {
            start_time = atof(token) / sysconf(_SC_CLK_TCK);
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
    fclose(status_file);

    // total_time: termination time of the process
    total_time = start_time + user + sys + cutime + cstime;
    // printf("total_time: %f, start_time: %f, user: %f, sys: %f, cutime: %f, cstime: %f\n", total_time, start_time, user, sys, cutime, cstime);

    char * signal_name = strsignal(si.si_status);
    // store signal name in exsig
    strcpy(exsig, signal_name);

    // save the extracted fields to struct in oneline
    process_info = (ProcessStat){extracted_pid, " ", state, excode, " ", ppid, user, sys, vctx, nvctx, total_time, 0};
    strcpy(process_info.cmd, cmd);
    strcpy(process_info.exsig, exsig);

    return process_info;
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

void execute_job(char *commands[], int num_commands) {
    int pipefd[MAX_COMMANDS - 1][2];
    int num_pipefds = num_commands - 1;

    sigset_t orig_mask;
    sigset_t set;

    // Create an array to store child process PIDs
    pid_t child_pids[MAX_COMMANDS];

    // Create pipes for inter-process communication
    for (int i = 0; i < num_commands - 1; i++) {
        if (pipe(pipefd[i]) == -1) {
            fprintf(stderr, "JCshell: Failure creating pipe\n");
            exit(1);
        }
    }

    // Fork child processes for each command
    for (int i = 0; i < num_commands; i++) {    // i: command index
        signal(SIGUSR1, sigusr1_handler);

        // Initialize a signal set containing SIGUSR1
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        // Block the signals in the set (prevent the signal from being delivered to the process)
        sigprocmask(SIG_BLOCK, &set, &orig_mask);
        
        // Fork a child process
        pid_t pid = fork();

        if (pid < 0) {
            fprintf(stderr, "JCshell: Error forking process\n");
            exit(1);
        } else if (pid == 0) {  // Child process
            sigset_t empty_mask;
            sigemptyset(&empty_mask);

            // Wait for the signal using sigsuspend
            sigsuspend(&empty_mask);

            // Unblock SIGUSR1 for the child process
            sigprocmask(SIG_SETMASK, &orig_mask, NULL);

            /*
            Pipe Logic: for current cmd (i), remove all except pfd[i-1][0] (stdin), and pfd[i][1] (stdout)
                        for first cmd (i == 0), pfd[i-1][0] index not valid
                        for last cmd (i == num_pipefds), pfd[i][1] index not valid
            Implementation (conditions):
                        (i == num_commands-1 && k == num_pipefds-1) means the last command
                        (i-1 == k) means the current pipe inputs to the current command
                        (i == 0 && k == 0) means the first command
                        (i == k) means the current pipe gets output from current command
            */
            for (int k = 0; k < num_pipefds; k++) { // k: pipefd index
                if ((i == num_commands-1 && k == num_pipefds-1) || i-1 == k) {
                    close(pipefd[k][1]);
                    dup2(pipefd[k][0], STDIN_FILENO);
                } else if ((i == 0 && k == 0) || i == k) {
                    close(pipefd[k][0]);
                    dup2(pipefd[k][1], STDOUT_FILENO);
                } else {
                    close(pipefd[k][0]);
                    close(pipefd[k][1]);
                }
            }
            
            // Execute the command
            execute_command(commands[i]);
        } else {    // Parent process
            signal(SIGINT, SIG_IGN);
            child_pids[i] = pid;
        }
        // here, the parent process will continue to fork the next child process
    }

    // Send SIGUSR1 to wake up child processes
    for (int i = 0; i < num_commands; i++) {
        // printf("Parent: sending SIGUSR1 to child process %d\n", child_pids[i]);
        kill(child_pids[i], SIGUSR1);
    }

    // Close all pipes in the parent process
    for (int i = 0; i < num_commands - 1; i++) {
        close(pipefd[i][0]);
        close(pipefd[i][1]);
    }

    // Wait for all child processes to terminate
    siginfo_t si[num_commands]; // array of siginfo_t
    for (int i = 0; i < num_commands; i++) {
        waitid(P_PID, child_pids[i], &si[i], WNOWAIT | WEXITED);
    }

    extract_stat(num_commands, child_pids, si);
}

/* Function to extract and print the stat, and remove process zombie state */
void extract_stat(int num_commands, pid_t child_pids[], siginfo_t si[]) {

    // a struct array to store the stats
    ProcessStat stat_arr[num_commands];
    for (int i = 0; i < num_commands; i++) {
        stat_arr[i] = get_process_stat(child_pids[i], si[i]);

        // Clear the zombie status and extract status and 
        int status;
        waitpid(child_pids[i], &status, 0);
        stat_arr[i].excode = WEXITSTATUS(status);   // (why doesn't match with /proc/<pid>/stat field 52?)
        if (WIFSIGNALED(status)){
            stat_arr[i].termBySig = true;
        } else { stat_arr[i].termBySig = false; }
    }

    // Sort stat_arr by total_time
    for (int j = 0; j < num_commands; j++) {
        for (int k = j+1; k < num_commands; k++) {
            if (stat_arr[j].total_time > stat_arr[k].total_time) {
                ProcessStat temp = stat_arr[j];
                stat_arr[j] = stat_arr[k];
                stat_arr[k] = temp;
            }
        }
    }   // bubble sort

    // Print stats in termination order
    printf("\n");
    for (int i = 0; i < num_commands; i++) {
        // Print EXSIG if the process is terminated by signal, otherwise print EXCODE
        if (stat_arr[i].termBySig) {    // Process is terminated by signal
            printf("(PID)%d (CMD)%s (STATE)%c (EXSIG)%s (PPID)%d (USER)%.2f (SYS)%.2f (VCTX)%lu (NVCTX)%lu\n", stat_arr[i].pid, stat_arr[i].cmd, stat_arr[i].state, stat_arr[i].exsig, stat_arr[i].ppid, stat_arr[i].user, stat_arr[i].sys, stat_arr[i].vctx, stat_arr[i].nvctx);
        } else {
            printf("(PID)%d (CMD)%s (STATE)%c (EXCODE)%d (PPID)%d (USER)%.2f (SYS)%.2f (VCTX)%lu (NVCTX)%lu\n", stat_arr[i].pid, stat_arr[i].cmd, stat_arr[i].state, stat_arr[i].excode, stat_arr[i].ppid, stat_arr[i].user, stat_arr[i].sys, stat_arr[i].vctx, stat_arr[i].nvctx);
        }
        // printf("(PID)%d (CMD)%s (STATE)%c (EXCODE)%d (EXSIG)%s (PPID)%d (USER)%.2f (SYS)%.2f (VCTX)%lu (NVCTX)%lu (Total_ime)%f (termBySig)%d\n", stat_arr[i].pid, stat_arr[i].cmd, stat_arr[i].state, stat_arr[i].excode, stat_arr[i].exsig, stat_arr[i].ppid, stat_arr[i].user, stat_arr[i].sys, stat_arr[i].vctx, stat_arr[i].nvctx, stat_arr[i].total_time, stat_arr[i].termBySig);
    }
}

/* Return error codes and messages:
    0: Valid input
    1: Exit
    2: Exit with other args
    3: Empty input
    4: Two consecutive pipes
    5: Pipe at the beginning
    6: Pipe at the end */ 
int validate_input(const char *input, int input_length) {

    // make a copy for input (to facilitate tokenization)
    char input_copy[MAX_COMMAND_LENGTH];
    strcpy(input_copy, input);

    // Tokenize the input by space
    char* token = strtok(input_copy, " ");
    // Check if the user wants to exit
    if (token != NULL && strcmp(token, "exit") == 0) {
        // Check for additional arguments from input
        token = strtok(NULL, " ");
        if (token != NULL) {
            // User entered "exit" with additional arguments
            fprintf(stderr, "JCshell: 'exit' with other arguments!!!\n");
            return 2;
        } else {
            // User only entered "exit"
            printf("JCshell: Terminated\n");
            return 1;
        }
    }

    // Check for empty input
    if (input_length == 0 || strspn(input, " ") == input_length) {
        // if input is empty or only spaces
        // fprintf(stderr, "JCshell: should not have empty input\n");
        return 3;
    }

    // Check for pipe syntax
    int consecutive_pipe = 0;
    for (int i = 0; i < input_length; i++) {
        if (input[i] == '|') {
            consecutive_pipe++;
            if (consecutive_pipe == 2) {
                fprintf(stderr, "JCshell: should not have two | symbols without in-between command\n");
                return 4;  // Two consecutive pipes
            }
        } else if (input[i] == ' ') {
            continue;
        } else {
            consecutive_pipe = 0;
        }
    }
    if (input[0] == '|') {
        fprintf(stderr, "JCshell: should not have a | symbol at the beginning of the command\n");
        return 5;  // Pipe at the beginning
    } else if (input[strlen(input) - 1] == '|') {
        fprintf(stderr, "JCshell: should not have a | symbol at the end of the command\n");
        return 6;  // Pipe at the end
    }

    // printf("JCshell: Valid input\n");
    return 0;  // Valid input
}

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
        // Install the SIGINT handler
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

        // Validate input to check for exit command and pipe syntax
        int error_code = validate_input(input, input_length);
        if (!error_code){
            // Valid input, execute the job
        } else if (error_code == 1) {
            break;    // Exit
        } else {
            continue; // Prompt for next input
        }

        // Tokenize the input into commands separated by pipes
        char *commands[MAX_COMMANDS];       // array of commands 
        int num_commands = 0;

        char* token = strtok(input, "|");
        while (token != NULL) {
            commands[num_commands++] = token;
            token = strtok(NULL, "|");
        }

        // print_cmds(commands, num_commands);

        // Execute the job
        execute_job(commands, num_commands);
    }

    return 0;
}

