# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # Specifies how Tasks should be distributed across Compute Nodes.
    #
    #
    class TaskSchedulingPolicy

      include MsRestAzure

      # @return [ComputeNodeFillType] How Tasks are distributed across Compute
      # Nodes in a Pool. If not specified, the default is spread. Possible
      # values include: 'spread', 'pack'
      attr_accessor :node_fill_type


      #
      # Mapper for TaskSchedulingPolicy class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'TaskSchedulingPolicy',
          type: {
            name: 'Composite',
            class_name: 'TaskSchedulingPolicy',
            model_properties: {
              node_fill_type: {
                client_side_validation: true,
                required: true,
                serialized_name: 'nodeFillType',
                type: {
                  name: 'Enum',
                  module: 'ComputeNodeFillType'
                }
              }
            }
          }
        }
      end
    end
  end
end
