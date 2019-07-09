# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # Options for removing Compute Nodes from a Pool.
    #
    #
    class NodeRemoveParameter

      include MsRestAzure

      # @return [Array<String>] A list containing the IDs of the Compute Nodes
      # to be removed from the specified Pool.
      attr_accessor :node_list

      # @return [Duration] The timeout for removal of Compute Nodes to the
      # Pool. The default value is 15 minutes. The minimum value is 5 minutes.
      # If you specify a value less than 5 minutes, the Batch service returns
      # an error; if you are calling the REST API directly, the HTTP status
      # code is 400 (Bad Request).
      attr_accessor :resize_timeout

      # @return [ComputeNodeDeallocationOption] Determines what to do with a
      # Compute Node and its running task(s) after it has been selected for
      # deallocation. The default value is requeue. Possible values include:
      # 'requeue', 'terminate', 'taskCompletion', 'retainedData'
      attr_accessor :node_deallocation_option


      #
      # Mapper for NodeRemoveParameter class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'NodeRemoveParameter',
          type: {
            name: 'Composite',
            class_name: 'NodeRemoveParameter',
            model_properties: {
              node_list: {
                client_side_validation: true,
                required: true,
                serialized_name: 'nodeList',
                constraints: {
                  MaxItems: 100
                },
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'StringElementType',
                      type: {
                        name: 'String'
                      }
                  }
                }
              },
              resize_timeout: {
                client_side_validation: true,
                required: false,
                serialized_name: 'resizeTimeout',
                type: {
                  name: 'TimeSpan'
                }
              },
              node_deallocation_option: {
                client_side_validation: true,
                required: false,
                serialized_name: 'nodeDeallocationOption',
                type: {
                  name: 'Enum',
                  module: 'ComputeNodeDeallocationOption'
                }
              }
            }
          }
        }
      end
    end
  end
end