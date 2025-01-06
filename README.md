# GoFuzzBuster 

This project implements *fuzz testing* for an authentication handler function, `AuthHandler`. The main goal of the fuzz testing is to ensure that the handler functions work correctly under different input conditions, including valid, invalid and malicious inputs (*e.g* SQL Injection).

The authentication handler checks username and password, ensuring they are valid and meet specific criteria. This repository provides a testing suite using Go's fuzz testing capabilities to verify the handler's behavior under various scenarios.

## Project Overview
The AuthHandler function accepts an HTTP POST request containing a JSON payload with a username and password. The function checks:
- Empty Fields: Ensures that the username and password fields are not empty.
- Username Constraints: Ensures the username is alphanumeric and includes only the characters -, _, and length between 3 and 20.
- Password Constraints: Ensures the password is alphanumeric with a length between 8 and 30.
- Authentication: If the username is admin and the password is 1234, authentication is successful.

Fuzz testing is employed to simulate different edge cases and validate the robustness of the handler.

## Authentication Handler
The AuthHandler function is responsible for authenticating user credentials. Here’s the core structure of the function:

```go
func AuthHandler(w http.ResponseWriter, r *http.Request) {
    // Logic to handle authentication
}
```

## Fuzz Testing
The project uses Go’s fuzzing capabilities to test the behavior of the AuthHandler. It validates both expected and unexpected inputs, ensuring the handler behaves as anticipated under a range of conditions.

### Fuzz Test Details
- Test Cases: Includes various scenarios like:
  - Empty fields
  - Valid usernames and passwords
  - Invalid characters
  - SQL injection attempts
- Execution: The fuzz test is executed using the testing.F framework, and the results are logged to help identify potential vulnerabilities.

```go
func FuzzAuthHandler(f *testing.F) {
    // Fuzz testing logic here
} 
```

## Installation
To run this project locally, you'll need Go installed on your machine.

Clone the repository:
```bash
git clone https://github.com/your-username/auth-handler-fuzz-testing.git
cd auth-handler-fuzz-testing
```
Install the necessary dependencies:
```bash
go mod tidy
```
## Usage
To run the fuzz tests, execute the following command:

bash
```bash
go test -fuzz=FuzzAuthHandler
```
This will start the fuzz testing process and log the results to the console.

## Contributing
We welcome contributions to this project! To contribute:

Fork the repository.
Create a new branch.
Implement your changes.
Write tests for any new functionality.
Submit a pull request with a description of your changes.
