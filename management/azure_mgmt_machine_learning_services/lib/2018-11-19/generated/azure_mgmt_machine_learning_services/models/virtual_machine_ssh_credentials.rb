# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::MachineLearningServices::Mgmt::V2018_11_19
  module Models
    #
    # Admin credentials for virtual machine
    #
    class VirtualMachineSshCredentials

      include MsRestAzure

      # @return [String] Username of admin account
      attr_accessor :username

      # @return [String] Password of admin account
      attr_accessor :password

      # @return [String] Public key data
      attr_accessor :public_key_data

      # @return [String] Private key data
      attr_accessor :private_key_data


      #
      # Mapper for VirtualMachineSshCredentials class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'VirtualMachineSshCredentials',
          type: {
            name: 'Composite',
            class_name: 'VirtualMachineSshCredentials',
            model_properties: {
              username: {
                client_side_validation: true,
                required: false,
                serialized_name: 'username',
                type: {
                  name: 'String'
                }
              },
              password: {
                client_side_validation: true,
                required: false,
                serialized_name: 'password',
                type: {
                  name: 'String'
                }
              },
              public_key_data: {
                client_side_validation: true,
                required: false,
                serialized_name: 'publicKeyData',
                type: {
                  name: 'String'
                }
              },
              private_key_data: {
                client_side_validation: true,
                required: false,
                serialized_name: 'privateKeyData',
                type: {
                  name: 'String'
                }
              }
            }
          }
        }
      end
    end
  end
end
