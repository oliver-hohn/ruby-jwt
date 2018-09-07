module JWT
  module Algos
    module Ps
      module_function

      SUPPORTED = %w[PS256 PS384 PS512].freeze

      def sign(to_sign)
        algorithm, msg, key = to_sign.values
        raise EncodeError, "The given key is a #{key.class}. It has to be an OpenSSL::PKey::RSA instance." if key.class == String

        key.sign_pss(algorithm.sub('PS', 'sha'), msg, salt_length: :digest, mgf1_hash: algorithm.sub('PS', 'sha'))
      end

      def verify(to_verify)
        algorithm, public_key, signing_input, signature = to_verify.values

        public_key.verify_pss(algorithm.sub('PS', 'sha'), signature, signing_input, salt_length: :auto, mgf1_hash: algorithm.sub('PS', 'sha'))
      end
    end
  end
end
