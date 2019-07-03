# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ServiceFabric::V6_5_0_36
  module Models
    #
    # Describes the operation to register or provision an application type
    # using an application package uploaded to the Service Fabric image store.
    #
    class ProvisionApplicationTypeDescription < ProvisionApplicationTypeDescriptionBase

      include MsRestAzure


      def initialize
        @Kind = "ImageStorePath"
      end

      attr_accessor :Kind

      # @return [String] The relative path for the application package in the
      # image store specified during the prior upload operation.
      attr_accessor :application_type_build_path

      # @return [ApplicationPackageCleanupPolicy] The kind of action that needs
      # to be taken for cleaning up the application package after successful
      # provision. Possible values include: 'Invalid', 'Default', 'Automatic',
      # 'Manual'
      attr_accessor :application_package_cleanup_policy


      #
      # Mapper for ProvisionApplicationTypeDescription class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ImageStorePath',
          type: {
            name: 'Composite',
            class_name: 'ProvisionApplicationTypeDescription',
            model_properties: {
              async: {
                client_side_validation: true,
                required: true,
                serialized_name: 'Async',
                type: {
                  name: 'Boolean'
                }
              },
              Kind: {
                client_side_validation: true,
                required: true,
                serialized_name: 'Kind',
                type: {
                  name: 'String'
                }
              },
              application_type_build_path: {
                client_side_validation: true,
                required: true,
                serialized_name: 'ApplicationTypeBuildPath',
                type: {
                  name: 'String'
                }
              },
              application_package_cleanup_policy: {
                client_side_validation: true,
                required: false,
                serialized_name: 'ApplicationPackageCleanupPolicy',
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
