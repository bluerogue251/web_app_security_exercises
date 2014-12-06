require 'chapter_2/vulnerable_script_tag_sanitizer'

describe Chapter2::VulnerableScriptTagSanitizer do
  let(:sanitizer) { Chapter2::VulnerableScriptTagSanitizer }

  it 'Strips any <script> tags that appear' do
    expect(sanitizer.sanitize('<script>')).to eq ''
  end

  it 'Strips any </script> tags that appear' do
    expect(sanitizer.sanitize('</script>')).to eq ''
  end

  it 'Truncates the input to 50 chars' do
    expect(sanitizer.sanitize('a' * 51)).to eq('a' * 50)
  end

  it 'Removes any quotation marks' do
    expect(sanitizer.sanitize('I am a "string')).to eq('I am a string')
  end

  it 'Decodes URLs' do
    expect(sanitizer.sanitize('Hello%20G%C3%BCnter')).to eq('Hello Günter')
  end

  it 'Repeats itself if any deletions were made' do
    fail
  end

  it 'Is has vulnerabilities' do
    expect(sanitizer.sanitize('malicious input')).to eq('“><script>alert(“foo”)</script>')
  end
end
