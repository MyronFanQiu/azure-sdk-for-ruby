# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Hdinsight::Mgmt::V2015_03_01_preview
  module Models
    #
    # Time and capacity request parameters
    #
    class AutoscaleTimeAndCapacity

      include MsRestAzure

      # @return [String] 24-hour time in the form xx:xx
      attr_accessor :time

      # @return [Integer] The minimum instance count of the cluster
      attr_accessor :min_instance_count

      # @return [Integer] The maximum instance count of the cluster
      attr_accessor :max_instance_count


      #
      # Mapper for AutoscaleTimeAndCapacity class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'AutoscaleTimeAndCapacity',
          type: {
            name: 'Composite',
            class_name: 'AutoscaleTimeAndCapacity',
            model_properties: {
              time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'time',
                type: {
                  name: 'String'
                }
              },
              min_instance_count: {
                client_side_validation: true,
                required: false,
                serialized_name: 'minInstanceCount',
                type: {
                  name: 'Number'
                }
              },
              max_instance_count: {
                client_side_validation: true,
                required: false,
                serialized_name: 'maxInstanceCount',
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
