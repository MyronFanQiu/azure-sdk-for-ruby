# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DataFactory::Mgmt::V2018_06_01
  module Models
    #
    # A linked service for an SSH File Transfer Protocol (SFTP) server.
    #
    class SftpServerLinkedService < LinkedService

      include MsRestAzure


      def initialize
        @type = "Sftp"
      end

      attr_accessor :type

      # @return The SFTP server host name. Type: string (or Expression with
      # resultType string).
      attr_accessor :host

      # @return The TCP port number that the SFTP server uses to listen for
      # client connections. Default value is 22. Type: integer (or Expression
      # with resultType integer), minimum: 0.
      attr_accessor :port

      # @return [SftpAuthenticationType] The authentication type to be used to
      # connect to the FTP server. Possible values include: 'Basic',
      # 'SshPublicKey'
      attr_accessor :authentication_type

      # @return The username used to log on to the SFTP server. Type: string
      # (or Expression with resultType string).
      attr_accessor :user_name

      # @return [SecretBase] Password to logon the SFTP server for Basic
      # authentication.
      attr_accessor :password

      # @return The encrypted credential used for authentication. Credentials
      # are encrypted using the integration runtime credential manager. Type:
      # string (or Expression with resultType string).
      attr_accessor :encrypted_credential

      # @return The SSH private key file path for SshPublicKey authentication.
      # Only valid for on-premises copy. For on-premises copy with SshPublicKey
      # authentication, either PrivateKeyPath or PrivateKeyContent should be
      # specified. SSH private key should be OpenSSH format. Type: string (or
      # Expression with resultType string).
      attr_accessor :private_key_path

      # @return [SecretBase] Base64 encoded SSH private key content for
      # SshPublicKey authentication. For on-premises copy with SshPublicKey
      # authentication, either PrivateKeyPath or PrivateKeyContent should be
      # specified. SSH private key should be OpenSSH format.
      attr_accessor :private_key_content

      # @return [SecretBase] The password to decrypt the SSH private key if the
      # SSH private key is encrypted.
      attr_accessor :pass_phrase

      # @return If true, skip the SSH host key validation. Default value is
      # false. Type: boolean (or Expression with resultType boolean).
      attr_accessor :skip_host_key_validation

      # @return The host key finger-print of the SFTP server. When
      # SkipHostKeyValidation is false, HostKeyFingerprint should be specified.
      # Type: string (or Expression with resultType string).
      attr_accessor :host_key_fingerprint


      #
      # Mapper for SftpServerLinkedService class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'Sftp',
          type: {
            name: 'Composite',
            class_name: 'SftpServerLinkedService',
            model_properties: {
              additional_properties: {
                client_side_validation: true,
                required: false,
                type: {
                  name: 'Dictionary',
                  value: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ObjectElementType',
                      type: {
                        name: 'Object'
                      }
                  }
                }
              },
              connect_via: {
                client_side_validation: true,
                required: false,
                serialized_name: 'connectVia',
                type: {
                  name: 'Composite',
                  class_name: 'IntegrationRuntimeReference'
                }
              },
              description: {
                client_side_validation: true,
                required: false,
                serialized_name: 'description',
                type: {
                  name: 'String'
                }
              },
              parameters: {
                client_side_validation: true,
                required: false,
                serialized_name: 'parameters',
                type: {
                  name: 'Dictionary',
                  value: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ParameterSpecificationElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'ParameterSpecification'
                      }
                  }
                }
              },
              annotations: {
                client_side_validation: true,
                required: false,
                serialized_name: 'annotations',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ObjectElementType',
                      type: {
                        name: 'Object'
                      }
                  }
                }
              },
              type: {
                client_side_validation: true,
                required: true,
                serialized_name: 'type',
                type: {
                  name: 'String'
                }
              },
              host: {
                client_side_validation: true,
                required: true,
                serialized_name: 'typeProperties.host',
                type: {
                  name: 'Object'
                }
              },
              port: {
                client_side_validation: true,
                required: false,
                serialized_name: 'typeProperties.port',
                type: {
                  name: 'Object'
                }
              },
              authentication_type: {
                client_side_validation: true,
                required: false,
                serialized_name: 'typeProperties.authenticationType',
                type: {
                  name: 'String'
                }
              },
              user_name: {
                client_side_validation: true,
                required: false,
                serialized_name: 'typeProperties.userName',
                type: {
                  name: 'Object'
                }
              },
              password: {
                client_side_validation: true,
                required: false,
                serialized_name: 'typeProperties.password',
                type: {
                  name: 'Composite',
                  polymorphic_discriminator: 'type',
                  uber_parent: 'SecretBase',
                  class_name: 'SecretBase'
                }
              },
              encrypted_credential: {
                client_side_validation: true,
                required: false,
                serialized_name: 'typeProperties.encryptedCredential',
                type: {
                  name: 'Object'
                }
              },
              private_key_path: {
                client_side_validation: true,
                required: false,
                serialized_name: 'typeProperties.privateKeyPath',
                type: {
                  name: 'Object'
                }
              },
              private_key_content: {
                client_side_validation: true,
                required: false,
                serialized_name: 'typeProperties.privateKeyContent',
                type: {
                  name: 'Composite',
                  polymorphic_discriminator: 'type',
                  uber_parent: 'SecretBase',
                  class_name: 'SecretBase'
                }
              },
              pass_phrase: {
                client_side_validation: true,
                required: false,
                serialized_name: 'typeProperties.passPhrase',
                type: {
                  name: 'Composite',
                  polymorphic_discriminator: 'type',
                  uber_parent: 'SecretBase',
                  class_name: 'SecretBase'
                }
              },
              skip_host_key_validation: {
                client_side_validation: true,
                required: false,
                serialized_name: 'typeProperties.skipHostKeyValidation',
                type: {
                  name: 'Object'
                }
              },
              host_key_fingerprint: {
                client_side_validation: true,
                required: false,
                serialized_name: 'typeProperties.hostKeyFingerprint',
                type: {
                  name: 'Object'
                }
              }
            }
          }
        }
      end
    end
  end
end
