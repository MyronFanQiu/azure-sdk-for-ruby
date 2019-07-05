# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # Specifies the parameters for the auto user that runs a Task on the Batch
    # service.
    #
    #
    class AutoUserSpecification

      include MsRestAzure

      # @return [AutoUserScope] The scope for the auto user. The default value
      # is Task. Possible values include: 'task', 'pool'
      attr_accessor :scope

      # @return [ElevationLevel] The elevation level of the auto user. The
      # default value is nonAdmin. Possible values include: 'nonAdmin', 'admin'
      attr_accessor :elevation_level


      #
      # Mapper for AutoUserSpecification class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'AutoUserSpecification',
          type: {
            name: 'Composite',
            class_name: 'AutoUserSpecification',
            model_properties: {
              scope: {
                client_side_validation: true,
                required: false,
                serialized_name: 'scope',
                type: {
                  name: 'Enum',
                  module: 'AutoUserScope'
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
              }
            }
          }
        }
      end
    end
  end
end
