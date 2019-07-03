# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ContainerRegistry::Mgmt::V2019_06_01_preview
  module Models
    #
    # The platform properties against which the run has to happen.
    #
    class PlatformProperties

      include MsRestAzure

      # @return [OS] The operating system type required for the run. Possible
      # values include: 'Windows', 'Linux'
      attr_accessor :os

      # @return [Architecture] The OS architecture. Possible values include:
      # 'amd64', 'x86', '386', 'arm', 'arm64'
      attr_accessor :architecture

      # @return [Variant] Variant of the CPU. Possible values include: 'v6',
      # 'v7', 'v8'
      attr_accessor :variant


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
              os: {
                client_side_validation: true,
                required: true,
                serialized_name: 'os',
                type: {
                  name: 'String'
                }
              },
              architecture: {
                client_side_validation: true,
                required: false,
                serialized_name: 'architecture',
                type: {
                  name: 'String'
                }
              },
              variant: {
                client_side_validation: true,
                required: false,
                serialized_name: 'variant',
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
