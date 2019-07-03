# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ServiceFabric::V6_5_0_36
  module Models
    #
    # Node Down event.
    #
    class NodeDownEvent < NodeEvent

      include MsRestAzure


      def initialize
        @Kind = "NodeDown"
      end

      attr_accessor :Kind

      # @return [Integer] Id of Node instance.
      attr_accessor :node_instance

      # @return [DateTime] Time when Node was last up.
      attr_accessor :last_node_up_at


      #
      # Mapper for NodeDownEvent class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'NodeDown',
          type: {
            name: 'Composite',
            class_name: 'NodeDownEvent',
            model_properties: {
              event_instance_id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'EventInstanceId',
                type: {
                  name: 'String'
                }
              },
              category: {
                client_side_validation: true,
                required: false,
                serialized_name: 'Category',
                type: {
                  name: 'String'
                }
              },
              time_stamp: {
                client_side_validation: true,
                required: true,
                serialized_name: 'TimeStamp',
                type: {
                  name: 'DateTime'
                }
              },
              has_correlated_events: {
                client_side_validation: true,
                required: false,
                serialized_name: 'HasCorrelatedEvents',
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
              node_name: {
                client_side_validation: true,
                required: true,
                serialized_name: 'NodeName',
                type: {
                  name: 'String'
                }
              },
              node_instance: {
                client_side_validation: true,
                required: true,
                serialized_name: 'NodeInstance',
                type: {
                  name: 'Number'
                }
              },
              last_node_up_at: {
                client_side_validation: true,
                required: true,
                serialized_name: 'LastNodeUpAt',
                type: {
                  name: 'DateTime'
                }
              }
            }
          }
        }
      end
    end
  end
end
