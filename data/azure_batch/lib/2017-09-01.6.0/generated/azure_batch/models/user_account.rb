# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  module Models
    #
    # Properties used to create a user used to execute tasks on an Azure Batch
    # node.
    #
    #
    class UserAccount

      include MsRestAzure

      # @return [String] The name of the user account.
      attr_accessor :name

      # @return [String] The password for the user account.
      attr_accessor :password

      # @return [ElevationLevel] The elevation level of the user account.
      # nonAdmin - The auto user is a standard user without elevated access.
      # admin - The auto user is a user with elevated access and operates with
      # full Administrator permissions. The default value is nonAdmin. Possible
      # values include: 'nonAdmin', 'admin'
      attr_accessor :elevation_level

      # @return [LinuxUserConfiguration] The Linux-specific user configuration
      # for the user account. This property is ignored if specified on a
      # Windows pool. If not specified, the user is created with the default
      # options.
      attr_accessor :linux_user_configuration


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
              }
            }
          }
        }
      end
    end
  end
end
