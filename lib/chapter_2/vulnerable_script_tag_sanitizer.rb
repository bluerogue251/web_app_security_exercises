require 'uri'

module Chapter2
  class VulnerableScriptTagSanitizer
    def self.sanitize(input)
      input.gsub!('<script>', '')
      input.gsub!('</script>', '')
      input = input[0..49]
      input.gsub!('"', '')
      URI.decode(input)
    end
  end
end
