# ush

A simple UNIX shell in C

## Features

- **Prompt**: Displays the current user, hostname, and working directory.
- **Command Execution**: Executes external commands from path or found in the systems' `PATH`.
- **Command Pipelines**: Supports chaining multiple commands together using the pipe `|` operator.
- **I/O Redirection**:
    - Redirects standard input from a file using `<`.
    - Redirects standard output to a file using `>`.
- **Background processes**; Runs commands int the background by appending `&` to the command line.
- **Built-in Commands**:
    - `cd`: Changes the current working directory.
    - `exit`: Terminates the shell session.
- **Job Control**: Automatically reports the termination of background processes.

---

## Getting Started

### Prerequisites

You'll need a C compiler like `gcc`.

### Compilation

Run the following command in your terminal:

```bash
gcc -o ush ush.c
```
### Running

To start the shell, execute the compiled binary:

```bash
./ush
```

You should see the `ush` prompt, ready to accept commands.

`user@hostname:/path/to/project$ `

---

## Usage Examples

- **Simple Command**

    ```
    ls -la
    ```

- **Output Redirection**

    ```
    ls -la > output.txt
    ```

- **Input Redirection**

    ```
    wc -l < output.txt
    ```

- **Pipeline**

    ```
    ls | xargs wc -l | sort -n
    ```
- **Combined I/O and Piping**

    ```
    cat < ush.c | grep main > main_function.txt
    ```

- **Background Job**

    ```
    sleep 10 &
    ```