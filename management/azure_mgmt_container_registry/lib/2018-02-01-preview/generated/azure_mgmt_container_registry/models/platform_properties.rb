# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ContainerRegistry::Mgmt::V2018_02_01_preview
  module Models
    #
    # The platform properties against which the build has to happen.
    #
    class PlatformProperties

      include MsRestAzure

      # @return [OsType] The operating system type required for the build.
      # Possible values include: 'Windows', 'Linux'
      attr_accessor :os_type

      # @return [Integer] The CPU configuration in terms of number of cores
      # required for the build.
      attr_accessor :cpu


      #
      # Mapper for PlatformProperties class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'PlatformProperties',
          type: {
            name: 'Composite',
            class_name: 'PlatformProperties',
            model_properties: {
              os_type: {
                client_side_validation: true,
                required: true,
                serialized_name: 'osType',
                type: {
                  name: 'String'
                }
              },
              cpu: {
                client_side_validation: true,
                required: false,
                serialized_name: 'cpu',
                type: {
                  name: 'Number'
                }
              }
            }
          }
        }
      end
    end
  end
end