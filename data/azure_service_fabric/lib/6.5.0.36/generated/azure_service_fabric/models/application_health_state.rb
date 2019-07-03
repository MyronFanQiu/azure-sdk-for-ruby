# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ServiceFabric::V6_5_0_36
  module Models
    #
    # Represents the health state of an application, which contains the
    # application identifier and the aggregated health state.
    #
    class ApplicationHealthState < EntityHealthState

      include MsRestAzure

      # @return [String] The name of the application, including the 'fabric:'
      # URI scheme.
      attr_accessor :name


      #
      # Mapper for ApplicationHealthState class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ApplicationHealthState',
          type: {
            name: 'Composite',
            class_name: 'ApplicationHealthState',
            model_properties: {
              aggregated_health_state: {
                client_side_validation: true,
                required: false,
                serialized_name: 'AggregatedHealthState',
                type: {
                  name: 'String'
                }
              },
              name: {
                client_side_validation: true,
                required: false,
                serialized_name: 'Name',
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
