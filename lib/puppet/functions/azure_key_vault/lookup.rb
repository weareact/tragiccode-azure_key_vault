require_relative '../../../puppet_x/tragiccode/azure'

Puppet::Functions.create_function(:'azure_key_vault::lookup') do
  dispatch :lookup_key do
    param 'Variant[String, Numeric]', :secret_name
    param 'Struct[{vault_name => String, vault_api_version => String, metadata_api_version => String}]', :options
    param 'Puppet::LookupContext', :context
  end

  def lookup_key(secret_name, options, context)
    # This is a reserved key name in hiera
    return context.not_found if secret_name == 'lookup_options'
    return context.cached_value(secret_name) if context.cache_has_key(secret_name)
    access_token = if context.cache_has_key('access_token')
                     context.cached_value('access_token')
                   else
                     token = TragicCode::Azure.get_access_token(options['metadata_api_version'])
                     context.cache('access_token', token)
                     token
                   end
    begin
      vault_secrets = if context.cache_has_key('vault_secrets')
                        context.cache_has_key('vault_secrets')
                      else
                        secrets = TragicCode::Azure.get_secrets(
                          options['vault_name'],
                          options['vault_api_version'],
                          access_token,)
                        context.cache('vault_secrets', secrets)
                        secrets
                      end
      secret_found = false
      for vault_secrets.each do |secret|
        if secret_name.include? secret['id']
        secret_found = true
        break
      end

      if secret_found
        secret_value = TragicCode::Azure.get_secret(
          options['vault_name'],
          secret_name,
          options['vault_api_version'],
          access_token,
          '',
        )
      else
        secret_value = nil
      end
    rescue RuntimeError => e
      Puppet.warning(e.message)
      secret_value = nil
    end
    context.not_found if secret_value.nil?
    return if secret_value.nil?
    context.cache(secret_name, secret_value)
  end
end
