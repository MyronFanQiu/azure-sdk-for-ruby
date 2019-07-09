# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # Properties used to create a user used to execute Tasks on an Azure Batch
    # Compute Node.
    #
    #
    class UserAccount

      include MsRestAzure

      # @return [String] The name of the user Account.
      attr_accessor :name

      # @return [String] The password for the user Account.
      attr_accessor :password

      # @return [ElevationLevel] The elevation level of the user Account. The
      # default value is nonAdmin. Possible values include: 'nonAdmin', 'admin'
      attr_accessor :elevation_level

      # @return [LinuxUserConfiguration] The Linux-specific user configuration
      # for the user Account. This property is ignored if specified on a
      # Windows Pool. If not specified, the user is created with the default
      # options.
      attr_accessor :linux_user_configuration

      # @return [WindowsUserConfiguration] The Windows-specific user
      # configuration for the user Account. This property can only be specified
      # if the user is on a Windows Pool. If not specified and on a Windows
      # Pool, the user is created with the default options.
      attr_accessor :windows_user_configuration


      #
      # Mapper for UserAccount class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'UserAccount',
          type: {
            name: 'Composite',
            class_name: 'UserAccount',
            model_properties: {
              name: {
                client_side_validation: true,
                required: true,
                serialized_name: 'name',
                type: {
                  name: 'String'
                }
              },
              password: {
                client_side_validation: true,
                required: true,
                serialized_name: 'password',
                type: {
                  name: 'String'
                }
              },
              elevation_level: {
                client_side_validation: true,
                required: false,
                serialized_name: 'elevationLevel',
                type: {
                  name: 'Enum',
                  module: 'ElevationLevel'
                }
              },
              linux_user_configuration: {
                client_side_validation: true,
                required: false,
                serialized_name: 'linuxUserConfiguration',
                type: {
                  name: 'Composite',
                  class_name: 'LinuxUserConfiguration'
                }
              },
              windows_user_configuration: {
                client_side_validation: true,
                required: false,
                serialized_name: 'windowsUserConfiguration',
                type: {
                  name: 'Composite',
                  class_name: 'WindowsUserConfiguration'
                }
              }
            }
          }
        }
      end
    end
  end
end