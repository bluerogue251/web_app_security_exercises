require 'uri'

module Chapter2
  class VulnerableScriptTagSanitizer
    def self.sanitize(input)
      repeat = true if input.gsub!('<script>', '')
      repeat = true if input.gsub!('</script>', '')
      repeat = true if input.length > 50
      input = input[0..49]
      repeat = true if input.gsub!('"', '')
      input = URI.decode(input)
      repeat ? sanitize(input) : input
    end
  end
end
