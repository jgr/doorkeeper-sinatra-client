# frozen_string_literal: true

require 'sinatra/base'
require 'securerandom'
require 'singleton'
require 'dotenv/load'
require './lib/html_renderer'
require 'signet/oauth_2/client'

Rollbar.configure do |config|
  config.access_token = ENV['ROLLBAR_ACCESS_TOKEN']
end

class App
  include Singleton

  attr_accessor :confidential_client_id,
                :confidential_client_secret,
                :confidential_client_redirect_uri,
                :authorization_url,
                :token_url
end

App.instance.tap do |app|
  app.confidential_client_id = ENV['CONFIDENTIAL_CLIENT_ID']
  app.confidential_client_secret = ENV['CONFIDENTIAL_CLIENT_SECRET']
  app.confidential_client_redirect_uri = ENV['CONFIDENTIAL_CLIENT_REDIRECT_URI']
  app.authorization_url = ENV['AUTHORIZATION_URL']
  app.token_url = ENV['TOKEN_URL']
end

class DoorkeeperClient < Sinatra::Base
  require 'rollbar/middleware/sinatra'
  use Rollbar::Middleware::Sinatra

  enable :sessions

  helpers do
    include Rack::Utils
    alias_method :h, :escape_html

    def pretty_json(json)
      JSON.pretty_generate(json)
    end

    def signed_in?
      !session[:access_token].nil?
    end

    def state_matches?(prev_state, new_state)
      return false if blank?(prev_state)
      return false if blank?(new_state)

      prev_state == new_state
    end

    def blank?(string)
      return true if string.nil?

      /\A[[:space:]]*\z/.match?(string.to_s)
    end

    def markdown(text)
      options  = { autolink: true, space_after_headers: true, fenced_code_blocks: true }
      markdown = Redcarpet::Markdown.new(HTMLRenderer, options)
      markdown.render(text)
    end

    def markdown_readme
      markdown(File.read(File.join(File.dirname(__FILE__), 'README.md')))
    end

    def site_host
      URI.parse(app.authorization_url).host
    end
  end

  def app
    App.instance
  end

  def generate_client
    Signet::OAuth2::Client.new(
      :authorization_uri => app.authorization_url,
      :token_credential_uri =>  app.token_url,
      :client_id => app.confidential_client_id,
      :client_secret => app.confidential_client_secret,
      :scope => 'search',
      :state => state,
      :redirect_uri => app.confidential_client_redirect_uri
    )
  end

  def generate_state!
    session[:state] = SecureRandom.hex
  end

  def state
    session[:state]
  end

  get '/' do
    erb :home
  end

  get '/sign_in' do
    generate_state!
    redirect generate_client.authorization_uri
  end

  get '/sign_out' do
    session[:access_token] = nil
    session[:refresh_token] = nil
    redirect '/'
  end

  get '/callback' do
    if params[:error]
      erb :callback_error, layout: !request.xhr?
    else
      unless state_matches?(state, params[:state])
        redirect '/'
        return
      end

      client = generate_client
      client.code = params[:code]
      client.fetch_access_token!

      session[:access_token]  = client.access_token
      session[:refresh_token] = client.refresh_token
      redirect '/'
    end
  end

  get '/refresh' do
    client = generate_client
    client.access_token = session[:access_token]
    client.refresh_token = session[:refresh_token]
    client.refresh!

    session[:access_token]  = client.access_token
    session[:refresh_token] = client.refresh_token
    redirect '/'
  rescue StandardError => _e
    erb :error, layout: !request.xhr?
  end
end
