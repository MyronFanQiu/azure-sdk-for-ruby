# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ServiceFabric::V6_5_0_36
  module Models
    #
    # Path description for the application package in the image store specified
    # during the prior copy operation.
    #
    class ApplicationTypeImageStorePath

      include MsRestAzure

      # @return [String] The relative image store path to the application
      # package.
      attr_accessor :application_type_build_path


      #
      # Mapper for ApplicationTypeImageStorePath class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ApplicationTypeImageStorePath',
          type: {
            name: 'Composite',
            class_name: 'ApplicationTypeImageStorePath',
            model_properties: {
              application_type_build_path: {
                client_side_validation: true,
                required: true,
                serialized_name: 'ApplicationTypeBuildPath',
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
