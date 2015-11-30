#define GSH_RL_BUFSIZE 1024
#define GSH_TOK_DELIM " \t\r\n\a"
#define GSH_TOK_BUFSIZE 64
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <time.h>

int gsh_cd(char **args);
int gsh_help(char **args);
int gsh_exit(char **args);
int gsh_showFiles(char **args);
int gsh_hideFiles(char **args);
char **gsh_split_line(char *line);
void gsh_loop(void);

//These declerations are for displaying the last login details
FILE *timeFile;
time_t rawtime;
struct tm* timeinfo;


void gsh_loop(void)
{
  char *line;
  char* shell_prompt[100];
  char **args;
  int status;
  char cwd[1024];
  char buff[255];
  //configure readline to auto-complete
  rl_bind_key('\t', rl_complete);
  timeFile = fopen("time.txt","r");
  if (timeFile != NULL)
    {
      fscanf(timeFile,"%s\n", buff);
      printf("%s ",buff);
      fgets(buff, 255, (FILE*)timeFile);
      printf("%s\r", buff);
      fclose(timeFile);
    }
  do {
    if (getcwd(cwd, sizeof(cwd)) != NULL)
      {
      const char delim[2] = "/";
      char *token;
      char *final;
      char result;
      token = strtok(cwd,delim);
      while (token != NULL)
	{
	  token =  strtok(NULL,delim);
	  if(token != NULL)
	    {
	      final = token;
	    }
	}
      //This is the prompt for the shell
      snprintf(shell_prompt, sizeof(shell_prompt),"%s:%s$> ",getenv("USER"),final);
      }
    line = readline(shell_prompt);
    if (!line)
      break;
    add_history(line);
    args = gsh_split_line(line);
    status = gsh_execute(args);

    free(line);
    free(args);
  } while (status);
}

char **gsh_split_line(char *line)
{
  int bufsize = GSH_TOK_BUFSIZE, position = 0;
  char **tokens = malloc(bufsize * sizeof(char*));
  char *token;

  if (!tokens) {
    fprintf(stderr, "g_shell: allocation error\n");
    exit(EXIT_FAILURE);
  }

  token = strtok(line, GSH_TOK_DELIM);
  while (token != NULL) {
    tokens[position] = token;
    position++;

    if (position >= bufsize) {
      bufsize += GSH_TOK_BUFSIZE;
      tokens = realloc(tokens, bufsize * sizeof(char*));
      if (!tokens) {
	fprintf(stderr, "g_shell: allocation error\n");
	exit(EXIT_FAILURE);
      }
    }

    token = strtok(NULL, GSH_TOK_DELIM);
  }
  tokens[position] = NULL;
  return tokens;
}


int gsh_launch(char **args)
{
  pid_t pid, wpid;
  int status;

  pid = fork();
  if(pid == 0) {
    // Child process
    if (execvp(args[0], args) == -1) {
      perror("g_shell");
    }
    exit(EXIT_FAILURE);
  } else if (pid < 0) {
    // Error forking
    perror("g_shell");
  } else {
    // Parent process
    do {
      wpid = waitpid(pid, &status, WUNTRACED);
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));
  }

  return 1;
}

char *builtin_str[] = {
  "cd",
  "help",
  "exit",
  "showFiles",
  "hideFiles"
};

int (*builtin_func[]) (char **) = {
  &gsh_cd,
  &gsh_help,
  &gsh_exit,
  &gsh_showFiles,
  &gsh_hideFiles
};

int gsh_num_builtins() {
  return sizeof(builtin_str) / sizeof(char *);
}

int gsh_cd(char **args)
{
  if (args[1] == NULL) {
    fprintf(stderr, "g_shell: expected argument t \"cd\"\n");
  } else {
    if (chdir(args[1]) != 0) {
	perror("g_shell");
      }
  }
  return 1;
}

int gsh_help(char **args)
{
  int i;
  printf("Ghost shell\n");
  printf("Enter program names and arguments, and hit enter.\n");
  printf("The following commands are built in:\n");

  for (i = 0; i < gsh_num_builtins(); i++) {
    printf(" %s\n", builtin_str[i]);
  }

  printf("Use the man command for information on other programs.\n");
  return 1;
}

int gsh_exit(char **args)
{
  //Write the time of exit to the time.txt file
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  timeFile = fopen("time.txt","w+");
  fprintf(timeFile,"Last login: %s\n", asctime(timeinfo));
  fclose(timeFile);
  return 0;
}

int gsh_showFiles(char **args)
{
  system("/bin/showFiles.app");
  return 1;
}

int gsh_hideFiles(char **args)
{
  system("/bin/hideFiles.app");
  return 1;
}


int gsh_execute(char **args)
{
  int i;

  if (args[0] == NULL) {
    // And empty command was entered
    return 1;
  }

  for (i = 0; i < gsh_num_builtins(); i++) {
    if (strcmp(args[0], builtin_str[i]) == 0) {
      return (*builtin_func[i])(args);
    }
  }

  return gsh_launch(args);
}

int main(int argc, char **argv)
{
  gsh_loop();

  return EXIT_SUCCESS;
}

