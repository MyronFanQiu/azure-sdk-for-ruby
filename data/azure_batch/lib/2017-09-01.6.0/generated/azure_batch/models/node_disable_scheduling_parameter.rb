# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  module Models
    #
    # Options for disabling scheduling on a compute node.
    #
    #
    class NodeDisableSchedulingParameter

      include MsRestAzure

      # @return [DisableComputeNodeSchedulingOption] What to do with currently
      # running tasks when disabling task scheduling on the compute node. The
      # default value is requeue. Possible values include: 'requeue',
      # 'terminate', 'taskCompletion'
      attr_accessor :node_disable_scheduling_option


      #
      # Mapper for NodeDisableSchedulingParameter class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'NodeDisableSchedulingParameter',
          type: {
            name: 'Composite',
            class_name: 'NodeDisableSchedulingParameter',
            model_properties: {
              node_disable_scheduling_option: {
                client_side_validation: true,
                required: false,
                serialized_name: 'nodeDisableSchedulingOption',
                type: {
                  name: 'Enum',
                  module: 'DisableComputeNodeSchedulingOption'
                }
              }
            }
          }
        }
      end
    end
  end
end
