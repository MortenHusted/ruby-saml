# generate_fixture.rb
require 'nokogiri'
require 'openssl'
require 'base64'
require 'securerandom'
require 'time'

# --- Configuration ---
SOURCE_ASSERTION_FILE = File.join(__dir__, 'test/responses/signed_nameid_in_atts.xml') # Or another sample assertion XML
SP_PUBLIC_CERT_FILE = File.join(__dir__, 'test/certificates/ruby-saml.crt')
OUTPUT_XML_FILE = File.join(__dir__, 'test/responses/generated_unsigned_message_aes256gcm_sha256_rsa_oaep_encrypted_signed_assertion.xml')
OUTPUT_BASE64_FILE = "#{OUTPUT_XML_FILE}.base64"

# Algorithm URIs
ALG_AES_256_GCM = 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
ALG_RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep'
ALG_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256' # Or 'http://www.w3.org/2001/04/xmldsig-more#sha256'

# Namespaces
NS = {
  'samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol',
  'saml' => 'urn:oasis:names:tc:SAML:2.0:assertion',
  'ds' => 'http://www.w3.org/2000/09/xmldsig#',
  'xenc' => 'http://www.w3.org/2001/04/xmlenc#'
}.freeze

# --- Helper Functions ---
def format_cert(cert_text)
  # Basic formatting like in test_helper
  cert_text = cert_text.gsub(/-----BEGIN CERTIFICATE-----/, "")
                 .gsub(/-----END CERTIFICATE-----/, "")
                 .gsub(/\s+/, "")
  "-----BEGIN CERTIFICATE-----\n#{cert_text.scan(/.{1,64}/).join("\n")}\n-----END CERTIFICATE-----\n"
end

# --- Main Logic ---

# 1. Load the source Assertion
begin
  source_doc = Nokogiri::XML(File.read(SOURCE_ASSERTION_FILE))
  assertion_node = source_doc.at_xpath('//saml:Assertion', NS)
  raise "Could not find saml:Assertion in #{SOURCE_ASSERTION_FILE}" unless assertion_node
  assertion_xml_string = assertion_node.canonicalize(Nokogiri::XML::XML_C14N_1_0)
rescue StandardError => e
  puts "Error loading source assertion: #{e.message}"
  exit 1
end

# 2. Load SP Public Key
begin
  sp_cert_pem = File.read(SP_PUBLIC_CERT_FILE)
  sp_cert = OpenSSL::X509::Certificate.new(format_cert(sp_cert_pem))
  sp_public_key = sp_cert.public_key
rescue StandardError => e
  puts "Error loading SP public key: #{e.message}"
  exit 1
end

# 3. Perform Encryption
encrypted_assertion_b64 = nil
encrypted_aes_key_b64 = nil
begin
  # --- AES-GCM Encryption (Data Encryption) ---
  aes_key = OpenSSL::Cipher.new('aes-256-gcm').random_key
  iv = SecureRandom.random_bytes(12)

  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.encrypt
  cipher.key = aes_key
  cipher.iv = iv

  encrypted_assertion_data = cipher.update(assertion_xml_string) + cipher.final
  auth_tag = cipher.auth_tag

  combined_payload = iv + encrypted_assertion_data + auth_tag
  encrypted_assertion_b64 = Base64.strict_encode64(combined_payload)

  # --- RSA-OAEP-SHA256 Encryption (Key Encryption) ---
  # Attempt using PKey#encrypt with options (requires openssl gem >= 3.0 likely)
  rsa_options = {
    "rsa_padding_mode": "oaep",
    "rsa_oaep_md": "sha256",
    "rsa_mgf1_md": "sha256"
  }

  # Check if the encrypt method exists and accepts options hash
  if sp_public_key.respond_to?(:encrypt) && sp_public_key.method(:encrypt).arity != 1 # Check if it accepts more than just data
      puts "Attempting RSA encryption with options: #{rsa_options}"
      encrypted_aes_key_data = sp_public_key.encrypt(aes_key, rsa_options)
      encrypted_aes_key_b64 = Base64.strict_encode64(encrypted_aes_key_data)
  else
      # Fallback or error if options are not supported
      puts "Warning: Your OpenSSL::PKey::RSA#encrypt method might not support options hash."
      puts "RSA key encryption will use default OAEP padding (likely SHA1)."
      # Example fallback using older #public_encrypt (likely uses SHA1 internally for OAEP)
      # encrypted_aes_key_data = sp_public_key.public_encrypt(aes_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      # encrypted_aes_key_b64 = Base64.strict_encode64(encrypted_aes_key_data)

      # Forcing placeholder if options aren't supported to avoid generating incorrect data
      encrypted_aes_key_b64 = Base64.strict_encode64("PLACEHOLDER_ENCRYPTED_AES_KEY_NEEDS_RSA_OAEP_SHA256_MANUALLY")
      puts "--> Using placeholder for EncryptedKey CipherValue."

  end


rescue OpenSSL::Cipher::CipherError => e
  puts "OpenSSL Cipher Error during AES-GCM encryption: #{e.message}"
  puts "Check if your OpenSSL version supports 'aes-256-gcm'."
  exit 1
rescue ArgumentError => e
  # Catch potential errors if encrypt options are invalid for the installed gem version
  puts "ArgumentError during RSA encryption (likely options hash not supported): #{e.message}"
  encrypted_aes_key_b64 = Base64.strict_encode64("PLACEHOLDER_ENCRYPTED_AES_KEY_NEEDS_RSA_OAEP_SHA256_MANUALLY")
  puts "--> Using placeholder for EncryptedKey CipherValue due to error."
rescue StandardError => e
   puts "Error during encryption step: #{e.message}"
   exit 1
end

# Ensure we have values before building XML
unless encrypted_assertion_b64 && encrypted_aes_key_b64
    puts "Encryption failed, cannot build XML."
    exit 1
end


# 4. Build the new Response XML structure
builder = Nokogiri::XML::Builder.new(encoding: 'UTF-8') do |xml|
  xml['samlp'].Response(
    'xmlns:samlp' => NS['samlp'],
    'xmlns:saml' => NS['saml'],
    'ID' => "_#{SecureRandom.hex(20)}",
    'Version' => '2.0',
    'IssueInstant' => Time.now.utc.iso8601,
    'Destination' => source_doc.root['Destination'] || 'http://example.com/acs',
    'InResponseTo' => source_doc.root['InResponseTo'] || "_#{SecureRandom.hex(10)}"
  ) do
    issuer_node = source_doc.at_xpath('//saml:Issuer', NS)
    if issuer_node
       xml.parent.add_child(issuer_node.dup)
    else
       xml['saml'].Issuer 'http://example-idp.com'
    end

    xml['samlp'].Status do
      xml['samlp'].StatusCode('Value' => 'urn:oasis:names:tc:SAML:2.0:status:Success')
    end

    xml['saml'].EncryptedAssertion do
      xml['xenc'].EncryptedData('xmlns:xenc' => NS['xenc'], 'Type' => 'http://www.w3.org/2001/04/xmlenc#Element') do
        xml['xenc'].EncryptionMethod('Algorithm' => ALG_AES_256_GCM)
        xml['ds'].KeyInfo('xmlns:ds' => NS['ds']) do
          xml['xenc'].EncryptedKey do
            xml['xenc'].EncryptionMethod('Algorithm' => ALG_RSA_OAEP) do
              xml['ds'].DigestMethod('Algorithm' => ALG_SHA256)
            end
            xml['xenc'].CipherData do
              # *** Insert Encrypted Key ***
              xml['xenc'].CipherValue encrypted_aes_key_b64
            end
          end
        end
        xml['xenc'].CipherData do
           # *** Insert Encrypted Assertion ***
          xml['xenc'].CipherValue encrypted_assertion_b64
        end
      end
    end
  end
end

output_xml = builder.to_xml(indent: 2)
output_base64 = Base64.strict_encode64(output_xml)

# 5. Save or Print Output
begin
  File.write(OUTPUT_XML_FILE, output_xml)
  File.write(OUTPUT_BASE64_FILE, output_base64)
  puts "Successfully generated XML structure with AES-GCM assertion to:"
  puts "- #{OUTPUT_XML_FILE}"
  puts "- #{OUTPUT_BASE64_FILE}"
  if encrypted_aes_key_b64.include?("PLACEHOLDER")
      puts "\nWARNING: RSA-OAEP-SHA256 key encryption failed or was not supported. The EncryptedKey CipherValue is a placeholder."
  else
      puts "\nNote: RSA-OAEP-SHA256 key encryption was attempted using OpenSSL::PKey#encrypt options."
  end
rescue StandardError => e
  puts "Error writing output files: #{e.message}"
  puts "\n--- Generated XML ---"
  puts output_xml
  puts "\n--- Base64 ---"
  puts output_base64
end