require 'net/http'
require 'json'
require 'logger'

module TragicCode
  # Azure API functions
  class Azure

    # Retrieves the federated token from a file or environment.
    def self.read_federated_token
      fed_token_file_path = "/var/run/secrets/azure/tokens/azure-identity-token"
      if File.exist?(fed_token_file_path)
        File.read(fed_token_file_path).strip
      else
        raise "No federated token found for workload identity."
      end
    end

    # Uses the workload identity flow (client credentials with JWT assertion) to get an access token.
    def self.get_workload_identity_token(tenant_id, client_id)
      fed_token = read_federated_token
      uri = URI("https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/token")
      headers = { 'Content-Type' => 'application/x-www-form-urlencoded' }
      req_body = URI.encode_www_form(
        'client_id'             => client_id,
        'grant_type'            => 'client_credentials',
        'client_assertion'      => fed_token,
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'scope'                 => 'https://vault.azure.net/.default'
      )

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      request = Net::HTTP::Post.new(uri.request_uri, headers)
      request.body = req_body
      response = http.request(request)
      raise "Workload identity token request failed with #{response.code}: #{response.body}" unless response.code.to_i == 200

      parsed = JSON.parse(response.body)
      parsed['access_token']
    end

    def self.get_access_token(api_version, client_id = nil)
      specified_client_id = client_id.nil? ? "" : "&client_id=#{client_id}"
      uri = URI("http://169.254.169.254/metadata/identity/oauth2/token?api-version=#{api_version}&resource=https%3A%2F%2Fvault.azure.net#{specified_client_id}")
      req = Net::HTTP::Get.new(uri.request_uri)
      req['Metadata'] = 'true'
      res = Net::HTTP.start(uri.hostname, uri.port) do |http|
        http.request(req)
      end
      raise res.body unless res.is_a?(Net::HTTPSuccess)
      JSON.parse(res.body)['access_token']
    end

    def self.get_secret(vault_name, secret_name, vault_api_version, access_token, secret_version)
      version_parameter = secret_version.empty? ? secret_version : "/#{secret_version}"
      uri = URI("https://#{vault_name}.vault.azure.net/secrets/#{secret_name}#{version_parameter}?api-version=#{vault_api_version}")
      req = Net::HTTP::Get.new(uri.request_uri)
      req['Authorization'] = "Bearer #{access_token}"
      res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
        http.request(req)
      end
      raise res.body unless res.is_a?(Net::HTTPSuccess)
      JSON.parse(res.body)['value']
    end

    def self.get_secrets(vault_name, vault_api_version, access_token)
      logger = Logger.new(STDOUT)
      logger.level = Logger::INFO
      logger.info("TragicCode::Azure::get_secrets - Getting secrets from Azure")
      uri = URI("https://#{vault_name}.vault.azure.net/secrets?api-version=#{vault_api_version}")
      req = Net::HTTP::Get.new(uri.request_uri)
      req['Authorization'] = "Bearer #{access_token}"
      res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
        http.request(req)
      end
      raise res.body unless res.is_a?(Net::HTTPSuccess)
      secrets_res = JSON.parse(res.body)['value']
      logger.debug("TragicCode::Azure::get_secrets - Initial secrets found: #{secrets_res}")
      next_page = JSON.parse(res.body)['nextLink']
      # Only log if there is no next page link
      logger.info("TragicCode::Azure::get_secrets - Only one page of secrets to get") if next_page.nil? or next_page.empty?
      until next_page.nil? or next_page.empty?
        logger.debug("TragicCode::Azure::get_secrets - Getting next page: #{next_page}")
        uri = URI(next_page)
        req = Net::HTTP::Get.new(uri.request_uri)
        req['Authorization'] = "Bearer #{access_token}"
        res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
          http.request(req)
        end
        raise res.body unless res.is_a?(Net::HTTPSuccess)
        logger.debug("TragicCode::Azure::get_secrets - Adding secrets: #{JSON.parse(res.body)['value']}")
        secrets_res = secrets_res + JSON.parse(res.body)['value']
        next_page = JSON.parse(res.body)['nextLink']
      end
      logger.debug("TragicCode::Azure::get_secrets - Found secrets: #{secrets_res}")
      return secrets_res
    end
  end
end
