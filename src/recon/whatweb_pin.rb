# WhatWeb resolves its target before consulting its configured proxy.
# This process-local shim returns only the trusted persisted binding.
require 'resolv'

class << Resolv
  def getaddress(name)
    return ENV.fetch('RECON_PIN_IP') if name.downcase == ENV.fetch('RECON_PIN_HOST')
    return '127.0.0.1' if name == '127.0.0.1'

    raise Resolv::ResolvError, 'name is outside the pinned target'
  end
end
