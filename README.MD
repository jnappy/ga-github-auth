# Give Me Curriculum

This is a simple Sinatra app that uses Gmail and GitHub OAuth to grant full-time instructors access to the appropriate course materials hosted on GitHub. 

Those requesting access must have a General Assembly email address and a GitHub account associated with that GA email. 

## Running the App

To get it running locally, you'll need to set a `.env` file with the following:

- a CLIENT_ID from GitHub.com
- a CLIENT_SECRET from GitHub.com 
- a GITHUB_ACCESS_TOKEN from a **[GA-WDI](https://github.com/ga-wdi) owner** 

The `.env` file should look like:

```
CLIENT_ID = "alphanumericstring"
CLIENT_SECRET = "alphanumericstring"
GITHUB_ACCESS_TOKEN = "alphanumericstring"

```
Once that file is set up: 

```bash
$ bundle install
```

...and then: 

```bash
$ ruby app.rb
```

---

This app is live @ https://github-ga-auth.herokuapp.com/