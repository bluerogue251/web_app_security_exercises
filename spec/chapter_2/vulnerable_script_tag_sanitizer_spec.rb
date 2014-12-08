require 'chapter_2/vulnerable_script_tag_sanitizer'

describe Chapter2::VulnerableScriptTagSanitizer do
  let(:sanitizer) { Chapter2::VulnerableScriptTagSanitizer }

  it 'Strips <script> tags' do
    expect(sanitizer.sanitize('<script>')).to eq ''
  end

  it 'Strips </script> tags' do
    expect(sanitizer.sanitize('</script>')).to eq ''
  end

  it 'Truncates the input to 50 chars' do
    expect(sanitizer.sanitize('a' * 51)).to eq('a' * 50)
  end

  it 'Removes quotation marks' do
    expect(sanitizer.sanitize('I am a "string')).to eq('I am a string')
  end

  it 'Decodes URLs' do
    expect(sanitizer.sanitize('Hello%20G%C3%BCnter')).to eq('Hello Günter')
  end

  it 'Removes multiple levels of script tags' do
    expect(sanitizer.sanitize('<sc<script></script>ript></sc</script>ript>')).to eq('')
  end

  it 'Removes quotation marks after they are decoded when something else malicious was found' do
    url_encoded_quotation_mark = URI.encode('"')
    expect(sanitizer.sanitize('<script>' + url_encoded_quotation_mark)).to eq('')
  end

  it 'Still has vulnerabilities' do
    expect(sanitizer.sanitize('%22>%3cscript>alert(%22foo%22)%3c/script>')).to eq('"><script>alert("foo")</script>')
  end
end
