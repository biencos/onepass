# Onepass
## _Store Your Passwords Safely_

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

Onepass is a safe password manager, that will help You store your passwords safely.

## Features
- Add a new password
- Encrypt and store safely new password
- Decrypt stored passwords with master password
- Safely configured environment


## Tech
Onepass uses this modules:
- [**python-dotenv**] - loading env variables
- [**Flask-Limiter**] - to protect against brute force attacks
- [**bcrypt**] - hashing password
- [**pycrypto**] - will be helpful during password encryption
- [**uuid**] - generating unique ids


## Installation
Onepass requires python 3 to run. 
Install the requirements and then start the server. Go to web folder and run: 
```sh
python run.py
```


## Docker
Instead of installing app You can very easily install and deploy it in a Docker container. You can run it by typing:

```sh
cd app
docker-compose up
```

This will create the docker image of app and pull in all of the necessary dependencies.
Once done, the sender app will be available under  **https://localhost:8080/** . 

## License

MIT