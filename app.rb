require 'google/apis/drive_v2'
require 'google/api_client/client_secrets'
require 'json'
require 'sinatra'
require 'pry'
require 'httparty'
require 'github_api'
require 'oauth'
require 'dotenv'

Dotenv.load

enable :sessions
set :session_secret, 'setme'

get '/' do
  erb :index
end

get '/oauth-request' do

  $course = @params['course']

  unless session.has_key?(:credentials)
    redirect to('/oauth2callback')
  end

  client_opts = JSON.parse(session[:credentials])
  id_token = client_opts["id_token"]
  email_address = HTTParty.get("https://www.googleapis.com/oauth2/v1/tokeninfo?id_token=" + id_token)['email']
  $ga_email = email_address.include?("@generalassemb.ly") ? true : false

  if $ga_email 
    redirect to("https://github.com/login/oauth/authorize?scope=user:email&client_id=#{ENV['CLIENT_ID']}&ga=1") 
  else
    erb :denied
  end
end

get '/oauth2callback' do

  if File.exists?('client_secrets.json')
    client_secrets = Google::APIClient::ClientSecrets.load
  else
    client_secrets = Google::APIClient::ClientSecrets.new(JSON.parse(ENV['GOOGLE_CLIENT_SECRET']))
  end
  auth_client = client_secrets.to_authorization

  auth_client.update!(
    :scope => 'https://www.googleapis.com/auth/userinfo.email',
    :redirect_uri => url('/oauth2callback'))

  if request['code'] == nil
    auth_uri = auth_client.authorization_uri.to_s
    redirect to(auth_uri)
  else
    auth_client.code = request['code']
    auth_client.fetch_access_token!
    auth_client.client_secret = nil
    session[:credentials] = auth_client.to_json
    redirect to('/oauth-request')
  end
end

get '/github-callback' do
  # get temporary GitHub code...
  session_code = request.env['rack.request.query_hash']['code']

  # ... and POST it back to GitHub
  options = {
    body: {
      code: session_code,
      client_id: ENV['CLIENT_ID'],
      client_secret: ENV['CLIENT_SECRET'],
    },
    headers: {
      "Content-Type" => "application/x-www-form-urlencoded",
      "Accept" => "application/json"
    }
  }

  result = HTTParty.post('https://github.com/login/oauth/access_token', options)
  access_token = result['access_token']
 
  options =  {
    body: {
      code: session_code,
      client_id: ENV['CLIENT_ID'],
      client_secret: ENV['CLIENT_SECRET'],
    },
      headers: {
      "Content-Type" => "application/x-www-form-urlencoded",
      "Accept" => "application/json",
      "User-Agent" => "ga-github-auth" 
    }, 
    params: {
      'access_token' => access_token
    }
  }

  response = HTTParty.get('https://api.github.com/user?access_token=' + access_token, options)
  @github_ga_login = response['login']
  @github_ga_email = (HTTParty.get('https://api.github.com/user/emails?access_token=' + access_token, options)[0]['email']).include?("@generalassemb.ly") ? true : false

    if ($ga_email and @github_ga_email)
       grant_permission(@github_ga_login, access_token) 
       if $course == "wdi" 
          redirect to("https://github.com/ga-wdi") 
        else     
          redirect to("https://github.com/generalassembly-studio") 
        end
    else
      erb :denied
    end

end


def grant_permission(user_name, access_token)

  team_ids = {
    "wdi" => "1744213", 
    "dsi" => "2020932", 
    "adi" => "1869399", 
    "iosi" => "2062807"
  }

  team_id = team_ids[$course]
  url = "https://api.github.com/teams/#{team_id}/memberships/#{user_name}?access_token="   

  options =  {
      headers: {
      "Content-Type" => "application/x-www-form-urlencoded",
      "Accept" => "application/json",
      "User-Agent" => "ga-github-auth" 
    }, 
    params: {
      'user_name' => 'jnappy'
    }
  }

  # this code below needs to have the owner access token, not the user's acces token 
  HTTParty.put(url + ENV['GITHUB_ACCESS_TOKEN'], options)
end
