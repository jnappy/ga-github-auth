## Automated GitHub Permissions for GA WDI Instructors

This is a simple Sinatra app that uses Gmail and GitHub OAuth to grant full-time instructors access to the appropriate course materials hosted on GitHub. 

Those requesting access must have a General Assembly email address and a GitHub account associated with that GA email. 

## Running the App

To get it running locally, you'll need to set a .env file with the following:

- a CLIENT_ID from GitHub.com
- a CLIENT_SECRET from GitHub.com 
- a GITHUB_ACCESS_TOKEN from an owner's account on GitHub.com 

The file should look like:

```.env

CLIENT_ID = "alphanumericstring"
CLIENT_SECRET = "alphanumericstring"
GITHUB_ACCESS_TOKEN = "alphanumericstring"

```
Once that file is set up: 

```bash
$ bundle install
```

...and then: 

```
$ ruby app.rb
```

---

This app is live @ https://github-ga-auth.herokuapp.com/