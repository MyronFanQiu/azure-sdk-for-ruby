# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_03_01_6_1
  module Models
    #
    # Properties used to create a user account on a Linux node.
    #
    #
    class LinuxUserConfiguration

      include MsRestAzure

      # @return [Integer] The user ID of the user account. The uid and gid
      # properties must be specified together or not at all. If not specified
      # the underlying operating system picks the uid.
      attr_accessor :uid

      # @return [Integer] The group ID for the user account. The uid and gid
      # properties must be specified together or not at all. If not specified
      # the underlying operating system picks the gid.
      attr_accessor :gid

      # @return [String] The SSH private key for the user account. The private
      # key must not be password protected. The private key is used to
      # automatically configure asymmetric-key based authentication for SSH
      # between nodes in a Linux pool when the pool's
      # enableInterNodeCommunication property is true (it is ignored if
      # enableInterNodeCommunication is false). It does this by placing the key
      # pair into the user's .ssh directory. If not specified, password-less
      # SSH is not configured between nodes (no modification of the user's .ssh
      # directory is done).
      attr_accessor :ssh_private_key


      #
      # Mapper for LinuxUserConfiguration class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'LinuxUserConfiguration',
          type: {
            name: 'Composite',
            class_name: 'LinuxUserConfiguration',
            model_properties: {
              uid: {
                client_side_validation: true,
                required: false,
                serialized_name: 'uid',
                type: {
                  name: 'Number'
                }
              },
              gid: {
                client_side_validation: true,
                required: false,
                serialized_name: 'gid',
                type: {
                  name: 'Number'
                }
              },
              ssh_private_key: {
                client_side_validation: true,
                required: false,
                serialized_name: 'sshPrivateKey',
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