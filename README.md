# Matrix Job Messenger

This repository contains a Python script designed to take outputs from various jobs and send them as encrypted messages to a Matrix room using the `matrix-nio[e2e]` library. It's an automated way to receive notifications in a Matrix room about the status or results of different tasks.

## Features

- Asynchronous login to Matrix server with password or token
- Automatic joining of invited rooms
- End-to-End encryption support for secure messaging
- Trusting unverified devices for E2E encryption
- Sending messages to a specified Matrix room
- Running custom tasks and sending their output to Matrix

## Prerequisites

Before you can run the script, you need to have the following installed:

- Python 3.6 or higher
- `matrix-nio[e2e]` library
- `python-dotenv` library for environment variable management

## Installation

1. Clone the repository to your local machine:

```bash
git clone https://github.com/Narakuku/matrix-job-messenger.git
cd matrix-job-messenger
```

2. Install the required Python libraries:

```bash
pip install matrix-nio[e2e] python-dotenv
```

3. Create a `.env` file in the root directory of the project with the following environment variables:

```plaintext
MATRIX_HOMESERVER_URL=https://your.matrix.server
MATRIX_USER_ID=@yourusername:matrix.server
MATRIX_PASSWORD=yourpassword
MATRIX_ROOM_ID=!yourroomid:matrix.server
MATRIX_STORE_PATH=path/to/your/store/directory
MATRIX_DEVICE_NAME=yourdevicename
```

## Usage

To run the script, simply execute the following command:

```bash
python3 matrix-job-messenger.py
```

The script will log in to the Matrix server, join rooms if invited, and start sending notifications to the specified room based on the output of the tasks defined in the script.

## Customizing Tasks

You can customize the tasks that the script will run and send notifications for. To do this, edit the `tasks_to_run` list in the `main` function to include your own tasks. Each task should be a coroutine function that returns a list of messages to be sent to the Matrix room.

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request if you have any improvements or bug fixes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
