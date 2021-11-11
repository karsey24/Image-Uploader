# Image-Uploader
A simple ShareX image uploader website, in NodeJS.  Uses ExpressJS and MongoDB.


## Setup
To get this project running, I recommend Ubuntu 20.04 with NodeJS, MongoDB and PM2 (for management).  
The project is meant to live in the /var/www directory, with uploads going to the /uploads folder.  
You can mount external storage of some sort (like a Block Storage Volume from Digital Ocean) as your uploads folder to help with scaling.  
Installing certbot or some mechanism for getting and renewing SSL certificates is highly recommended.

## Configuration
Plenty of online guides can help with the installation of software.  What you still need is to set up the mailing API with your own 
template and secret key.  You also need to update the list of domains in the config file, along with the IP of the server.

There is not an admin account.  Browse the directory of images if you want to moderate the content.

rateLimiter.js can be configured to help with DDoS attacks.

## That's all.
I'm not planning on updating this in the future.  I know the NodeJS code is a mess, but it's my first *real* Node project and I wanted 
to make it quickly.  This whole thing took just a couple days for me to make.
