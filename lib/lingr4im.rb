require 'rubygems'
require 'blather/client/dsl'
require 'em-http'
require 'yaml'
require 'json'
require 'logger'
require 'sequel'
require 'base64'


module Lingr4IM
  extend Blather::DSL

  RETRY_MAX = 4
  WAIT_TIME = 1
  ERROR_WAIT_TIME = 60
  TIMEOUT = 30
  CONFIG = YAML.load_file(File.dirname(__FILE__) + '/config/app.yml')
  
  log_file = CONFIG['log_file'] || STDOUT
  @@logger = Logger.new(log_file)
  case CONFIG['log_level']
  when /^debug$/i
    @@logger.level = Logger::DEBUG
  when /^info$/i
    @@logger.level = Logger::INFO
  when /^warn$/i
    @@logger.level = Logger::WARN
  when /^error$/i
    @@logger.level = Logger::ERROR
  when /^fatal$/i
    @@logger.level = Logger::FATAL
  end
  Sequel.connect("mysql://#{CONFIG['db_user']}:#{CONFIG['db_pass']}@#{CONFIG['db_host']}/#{CONFIG['db_scheme']}", {
    :engine => 'InnoDB',
    :charset => 'utf8',
    :collate => 'utf8_bin'
  })
  Sequel::MySQL.default_engine = 'InnoDB'
  Sequel::MySQL.default_charset = 'utf8'
  Sequel::MySQL.default_collate = 'utf8_bin'
  Sequel::Model.plugin :schema
  Sequel::Model.plugin :touch
  module ::Sequel
    extension :blank
  end

  class << self
    ['debug', 'info', 'warn', 'error', 'fatal'].each do |name|
      define_method (name) do |message|
        @@logger.__send__ name, message
      end
    end

    def run
      client.run
      debug 'running'
    end

    def vcard!
      iq = Blather::Stanza::Iq::Vcard.new :set
      iq.vcard['NICKNAME'] = 'Lingr'
      iq.vcard['FN'] = 'Lingr4IM'
      iq.vcard['PHOTO/TYPE'] = "image/png"
      icon = File.new(File.dirname(__FILE__) + "/#{CONFIG['icon']}", "r")
      base64ed = Base64.b64encode(icon.read)
      icon.rewind
      iq.vcard['PHOTO/BINVAL'] = base64ed
      client.write_with_handler iq do |response|
        debug response
      end
    end

    def help msg
      say msg.from, <<EOH
usage:
[messages]
\tsay messages current room
/login [user] [password]
\tlogin lingr
/logout
\tlogout lingr
/rooms
\tshow available rooms
/join [room]
\tjoin  specified room
/show [room]
\tshow old messages on specified room
/leave [room]
\tleave specified room
/current
\tshow current room
/on
\tstart observing
/off
\tstop observing
/switch [room]
\tswitch current room to specified room
/say [room] [messages]
\tsay messages to specified room
/help
\tshow this message
EOH
      nil
    end

    def template status
      <<EOT
#{status['nickname']}(#{status['speaker_id'] || status['username']})@#{status['room']}:
#{status['text']}
EOT
    end

    def subscribe opts
      room = opts[:room]
      user = opts[:user]
      user.set(:current_room => room).save_changes
      Lingr.subscribe(
        :session => user.session,
        :room => room,
        :callback => Proc.new{|json|
          if json['status'] == 'ok'
            UserRoom.find_or_create(
              :user_id => user.id, :room => room
            ).set(:subscribed => true).save_changes
            user.set(:counter => json['counter']).save_changes
            say user.jid, "joined #{room}"
          else
            say user.jid, "#{json['status']}: #{json['detail']}"
          end
        },
        :errback => Proc.new{|response|
          say user.jid, response
        }
      )
    end

    def observe opts
      user = opts[:user]
      unless user.observed
        debug "start observing"
        user.set(:observed => true).save_changes
        Lingr.observe(
          :session => user.session,
          :counter => user.counter,
          :on_stream => Proc.new{|json|
            retry_ok = User.filter(:jid => user.jid).first.observed
            next unless retry_ok
            if json['status'] == 'ok'
              json['events'].each do |evt|
                status = evt['message'] || evt['presence']
                say user.jid, template(status) unless status.nil?
              end
              counter = json['counter']
              user.set(:counter => counter).save_changes unless counter.nil?
            else
              user.set(:observed => false).save_changes
              say user.jid, "#{json['status']}: #{json['detail']}"
            end
            retry_ok
          },
          :callback => Proc.new{|response|
            retry_ok = User.filter(:jid => user.jid).first.observed
            retry_ok
          },
          :errback => Proc.new{|response|
            retry_ok = User.filter(:jid => user.jid).first.observed
            retry_ok
          }
        )
      end
    end

    def activate user
      current_room = user.current_room
      user.user_rooms.each do |user_room|
        subscribe :user => user, :room => user_room.room if user_room.subscribed
      end
      user.set(:current_room => current_room).save_changes
      if user.observed
        user.set(:observed => false).save_changes
        observe :user => user
      end
    end
  end

  setup CONFIG['jid'], CONFIG['jpassword']

  when_ready do
    vcard!
    users = User.all
    unless users.blank?
      users.each do |user|
        activate user
      end
    end
  end

  # login command
  message :chat?, :body => %r{^/login\s+(?:\w+)\s(?:\w+)$} do |msg|
    return help msg unless %r{^/login\s+(\w+)\s(\w+)$} =~ msg.body
    _user = $1
    _password = $2
    Lingr.login(
      :message => msg, :user => _user, :password => _password,
      :callback => Proc.new{|json|
        info json
        info msg.from
        jid = User.normalize_jid(msg.from)
        user = User.find_or_create(:jid => jid)
        user.set(
          :username => json['user']['username'],
          :session => json['session'],
          :public_id => json['public_id']
        ).save_changes
        say user.jid, 'logged in'
      },
      :errback => Proc.new{|response|
        say msg.from, response
      }
    )
  end
  
  # logout command
  message :chat?, :body => %r{^/logout$} do |msg|
    user = User.from_message(msg)
    Lingr.logout(
      :session => user.session,
      :callback => Proc.new{|json|
        user.set(:observed => false).save_changes
        say user.jid, 'logout lingr'
      },
      :errback => Proc.new{|response|
        say user.jid, response
      }
    )
  end

  # rooms
  message :chat?, :body => %r{^/rooms$} do |msg|
    user = User.from_message(msg)
    Lingr.rooms(
      :session => user.session,
      :callback => Proc.new{|json|
        say user.jid, json['rooms'].join(', ')
      },
      :errback => Proc.new{|response|
        say user.jid, response
      }
    )
  end

  # join
  message :chat?, :body => %r{^/(?:join)\s+(?:\w+)$} do |msg|
    return help msg unless %r{^/join\s+(\w+)$} =~ msg.body
    user = User.from_message(msg)
    room = $1
    subscribe :user => user, :room => room
  end

  # show room
  message :chat?, :body => %r{^/show} do |msg|
    user = User.from_message(msg)
    room = (%r{^/show\s+(\w+)$} =~ msg.body) ? $1 : user.current_room
    if room.empty?
      say user.jid, "required room or joined some room"
      return
    end
    Lingr.show(
      :session => user.session,
      :room => room,
      :callback => Proc.new{|json|
        json['rooms'][0]['messages'].each do |status|
          say user.jid, template(status)
        end
      },
      :errback => Proc.new{|response|
        say user.jid, response
      }
    )
  end

  # show room archive
  message :chat?, :body => %r{^/archive\s+(?:\w+)\s+(?:\d+)$} do |msg|
    return help msg unless %r{^/archive\s+(\w+)\s+(\d+)$} =~ msg.body
    user = User.from_message(msg)
    room = $1
    before = $2
    Lingr.archive(
      :session => user.session,
      :room => room,
      :before => before,
      :callback => Proc.new {|json|
        debug json
        json['rooms'][0]['messages'].each do |status|
          say user.jid, template(status)
        end
      },
      :errback => Proc.new{|response|
        say user.jid, response
      }
    )
  end

  #leave
  message :chat?, :body => %r{^/leave} do |msg|
    user = User.from_message(msg)
    room = (%r{^/leave\s+(\w+)$} =~ msg.body) ? $1 : user.current_room
    if room.empty?
      say user.jid, "required room or joined some room"
      return
    end
    Lingr.unsubscribe(
      :session => user.session,
      :room => room,
      :callback => Proc.new{|json|
        debug json
        UserRoom.find_or_create(
          :user_id => user.id, :room => room
        ).set(
          :subscribed => false
        ).save_changes
        say user.jid, "leave #{room}"
      },
      :errback => Proc.new{|response|
        say user.jid, response
      }
    )
  end

  #current
  message :chat?, :body => %r{^/current} do |msg|
    user = User.from_message(msg)
    say user.jid, user.current_room
  end

  #on
  message :chat?, :body => %r{^/on} do |msg|
    user = User.from_message(msg)
    unless user.observed
      user.set(:observed => true).save_changes
      activate user
      say user.jid, "start observing"
    end
  end

  #off
  message :chat?, :body => %r{^/off} do |msg|
    user = User.from_message(msg)
    user.set(:observed => false).save_changes
    say user.jid, "stop observing"
  end

  #switch
  message :chat?, :body => %r{^/switch\s(?:\w+)$} do |msg|
    return help msg unless %r{^/switch\s+(\w+)$} =~ msg.body
    room = $1
    user = User.from_message(msg)
    user_room = UserRoom.filter(:user_id => user.id, :room => room).first
    if user_room.blank?
      say user.jid, "join #{room} before switch"
    else
      user.set(:current_room => room).save_changes
      say user.jid, "changed current room to #{room}"
    end
  end

  # say
  message :chat?, :body =>%r{^/say\s+(?:\w+)\s+(?:.+)$} do |msg|
    return help msg unless %r{^/say\s+(\w+)\s+(.+)$} =~ msg.body
    user = User.from_message(msg)
    room = $1
    text = $2
    Lingr.say(
      :session => user.session,
      :room => room,
      :text => text,
      :callback => Proc.new{|json|
        debug json
      },
      :errback => Proc.new{|res|
        say user.jid, res
      }
    )
  end

  #help
  message :chat?, :body => %r{^/} do |msg|
    help msg
  end

  # say current room
  message :chat?, :body => %r{^[^/]} do |msg|
    user = User.from_message(msg)
    return if user.current_room.nil?
    Lingr.say(
      :session => user.session,
      :room => user.current_room,
      :text => msg.body,
      :errback => Proc.new{|res|
        say user.jid, res
      }
    )
  end

  # auto approve
  subscription :request? do |s|
    write_to_stream s.approve!
    jid = User.normalize_jid(s.from)
    User.find_or_create(:jid => jid)
  end

  # auto unsubscribe
  subscription :unsubscribe? do |s|
    write_to_stream s.unsubscribe!
    user = User.from_message(s)
    user.remove_all_user_rooms
    user.destroy
  end


  class Lingr
    END_POINT_BASE = 'http://lingr.com'
    class << self
      def login opts
        end_point = "#{END_POINT_BASE}/api/session/create"
        query = {
          'user' => opts.delete(:user),
          'password' => opts.delete(:password)
        }
        request(end_point, query, opts)
      end

      def verify opts
        end_point = "#{END_POINT_BASE}/api/session/verify"
        query = {'session' => opts.delete(:session)}
        request(end_point, query, opts)
      end

      def logout opts
        end_point = "#{END_POINT_BASE}/api/session/destroy"
        query = {'session' => opts.delete(:session)}
        request(end_point, query, opts)
      end

      def show  opts
        end_point = "#{END_POINT_BASE}/api/room/show"
        query = {
          'session' => opts.delete(:session),
          'room' => opts.delete(:room)
        }
        request(end_point, query, opts)
      end

      def archive opts
        end_point = "#{END_POINT_BASE}/api/room/get_archives"
        query = {
          'session' => opts.delete(:session),
          'room' => opts.delete(:room),
          'before' => opts.delete(:before),
        }
        request(end_point, query, opts)
      end

      def subscribe opts
        end_point = "#{END_POINT_BASE}/api/room/subscribe"
        query = {
          'session' => opts.delete(:session),
          'room' => opts.delete(:room)
        }
        request(end_point, query, opts)
      end

      def unsubscribe opts
        end_point = "#{END_POINT_BASE}/api/room/unsubscribe"
        query = {
          'session' => opts.delete(:session),
          'room' => opts.delete(:room)
        }
        request(end_point, query, opts)
      end

      def say opts
        end_point = "#{END_POINT_BASE}/api/room/say"
        query = {
          'session' => opts.delete(:session),
          'room' => opts.delete(:room),
          'text' => opts.delete(:text)
        }
        request(end_point, query, opts)
      end

      def rooms opts
        end_point = "#{END_POINT_BASE}/api/user/get_rooms"
        query = {'session' => opts.delete(:session)}
        request(end_point, query, opts)
      end

      def observe opts
        end_point = "#{END_POINT_BASE}:8080/api/event/observe"
        opts_tmp = opts.dup
        query = {
          'app_key' => CONFIG['app_key'],
          'app_secret' => CONFIG['app_secret'],
          'session' => opts.delete(:session),
          'counter' => opts.delete(:counter)
        }
        http = EM::HttpRequest.new(end_point).get(
          :timeout => TIMEOUT, :query => query
        )
        buffer = nil
        counter = query['counter']
        retry_ok = true
        http.stream do |chunk|
          next unless retry_ok
          trimed = chunk.gsub(/\r\n/m,'')
          buffer = buffer.nil? ? trimed : buffer + trimed
          json = JSON.parse(buffer) rescue next
          buffer = nil
          counter = json['counter']
          retry_ok = opts[:on_stream].call(json) unless opts[:on_stream].nil?
        end
        http.callback do
          retry_ok = opts[:callback].call(http.response) unless opts[:callback].nil?
          if retry_ok
            sleep WAIT_TIME
            opts_tmp[:counter] = counter
            observe opts_tmp
          end
        end
        http.errback do
          retry_ok = opts[:errback].call(http.response) unless opts[:errback].nil?
          if http.response_header.status.to_i == 0 and retry_ok
            Lingr4IM.info 'connection close..'
            sleep WAIT_TIME
            opts_tmp[:counter] = counter
            observe opts_tmp
          else
            Lingr4IM.error "status: #{http.response_header.status}"
            Lingr4IM.error "header: #{http.response_header}"
            Lingr4IM.error "response: #{http.response}"
          end
        end
      end

      private

      def request end_point, query = {}, opts = {}
        q = {'app_key' => CONFIG['app_key'], 'app_secret' => CONFIG['app_secret']}
        q.merge!(query) unless query.nil?
        http = EM::HttpRequest.new(end_point).get(
          :timeout => TIMEOUT, :query => q
        )
        
        http.callback do
          json = JSON.parse(http.response)
          opts[:callback].call(json) unless opts[:callback].nil?
        end
        http.errback do
          Lingr4IM.error "end_point: #{end_point}"
          Lingr4IM.error "status: #{http.response_header.status}"
          Lingr4IM.error "header: #{http.response_header}"
          Lingr4IM.error "response: #{http.response}"
          Lingr4IM.error "query: #{q.to_json}"
          opts[:errback].call(http.response) unless opts[:errback].nil?
        end
      end
    end
  end

  class User < Sequel::Model
    plugin :timestamps, :update_on_create => true
    unless table_exists?
      set_schema do
        Integer :id, :primary_key => true ,:null => false, :unsigned => true, :auto_increment => true
        String :jid, :null => false, :unique => true
        String :username, :null => false, :index => true, :default => ''
        String :email, :null => false, :index => true, :default => ''
        String :public_id, :null => false, :default => ''
        String :session, :null => false, :default => ''
        String :current_room, :null => false, :default => ''
        boolean :observed, :null => false, :default => false
        Bignum :counter, :null => false, :default => 0
        timestamp :updated_at, :null => false
        timestamp :created_at, :null => false
      end
      create_table
    end
    one_to_many :user_rooms

    def self.from_message msg
      User.filter(:jid => normalize_jid(msg.from)).first
    end

    def self.normalize_jid jid
      jid.to_s.split('/')[0]
    end
  end

  class UserRoom < Sequel::Model
    plugin :timestamps, :update_on_create => true
    unless table_exists?
      set_schema do
        Integer :id, :primary_key => true ,:null => false, :unsigned => true, :auto_increment => true
        Integer :user_id, :null => false, :unsigned => true, :index => true
        String :room, :null => false, :index => true
        boolean :subscribed, :null => false, :default => false
        timestamp :updated_at, :null => false
        timestamp :created_at, :null => false
        unique [:user_id, :room]
      end
      create_table
    end
    many_to_one :user
  end
end

if $0 == __FILE__
  trap(:INT) { EM.stop }
  trap(:TERM) { EM.stop }
  EM.run do
    Lingr4IM.run
  end
end
