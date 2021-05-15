# Onepass
## _Store Your Passwords Safely_

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

Onepass is a safe password manager, that will help You store your login details safely.

## Features
- Register in manager
- Login to your account in manager
- Add a new password
- Encrypt and store safely new password
- Show all saved passwords with additional info about them (name of service, url to service, ...)
- Decrypt choosen password (with master password)
- Decrypt all saved passwords (with master password)
- Generate Safe Password
- Secure, offline access


## Tech
**Python**, **SQLite** were used to create the application. In addition, the following libraries were used:
- [**python-dotenv**] - loading env variables
- [**bcrypt**] - hashing user password
- [**pycrypto**] - helpful for passwords encryption
- [**uuid**] - generating unique ids


## Installation
Onepass requires python 3 to run.

But before running onepass You need to install all the requirements for the project. 
To do this, go to onepass folder and type:
```sh
python -m pip install -r requirements.txt
```
> Note:  If your **version of python is less than 3.6**, then You need to **install secrets package**.
> To do this, uncomment the last line of requirements.txt

Now, when all required packages are installed, You can run app by typing: 
```sh
python run.py
```


## License

MIT