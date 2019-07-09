# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_12_01_8_0
  module Models
    #
    # The number of nodes in each state for a pool.
    #
    #
    class PoolNodeCounts

      include MsRestAzure

      # @return [String] The ID of the pool.
      attr_accessor :pool_id

      # @return [NodeCounts] The number of dedicated nodes in each state.
      attr_accessor :dedicated

      # @return [NodeCounts] The number of low priority nodes in each state.
      attr_accessor :low_priority


      #
      # Mapper for PoolNodeCounts class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'PoolNodeCounts',
          type: {
            name: 'Composite',
            class_name: 'PoolNodeCounts',
            model_properties: {
              pool_id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'poolId',
                type: {
                  name: 'String'
                }
              },
              dedicated: {
                client_side_validation: true,
                required: false,
                serialized_name: 'dedicated',
                type: {
                  name: 'Composite',
                  class_name: 'NodeCounts'
                }
              },
              low_priority: {
                client_side_validation: true,
                required: false,
                serialized_name: 'lowPriority',
                type: {
                  name: 'Composite',
                  class_name: 'NodeCounts'
                }
              }
            }
          }
        }
      end
    end
  end
end