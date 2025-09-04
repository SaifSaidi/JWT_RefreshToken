# ASP.NET Core API with JWT and Refresh Token

This project is a simple demonstration of how to implement JWT (JSON Web Token) and Refresh Token authentication in an ASP.NET Core API. It provides a basic setup for user registration, login, and token-based authentication.

## About the Project

This project is a learning resource for understanding how to secure an ASP.NET Core API using JWT and Refresh Tokens. It includes the following features:

*   User registration and login
*   JWT-based authentication for securing API endpoints
*   Refresh token mechanism for renewing expired JWTs
*   Role-based authorization (Admin and User roles)
*   A simple and clean architecture for easy understanding

## Getting Started

To get a local copy up and running, follow these simple steps.

### Prerequisites

*   [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
*   [SQL Server](https://www.microsoft.com/en-us/sql-server/sql-server-downloads) (or any other database compatible with Entity Framework Core)

## Usage

You can use a tool like [Postman](https://www.postman.com/) or [Scalar UI] to interact with the API.

### API Endpoints

*   `POST /api/Auth/Register`: Register a new user.
*   `POST /api/Auth/Login`: Log in a user and get a JWT and refresh token.
*   `POST /api/Auth/Refresh-Token`: Get a new JWT using a refresh token.
*   `POST /api/Auth/Revoke-Token`: Revoke a refresh token.
*   `GET /api/Users`: Get a list of all users (Admin only).
*   `GET /api/Users/profile`: Get the profile of the current user.
*   `GET /api/Admin`: Access an admin-only endpoint.
