# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_12_01_8_0
  module Models
    #
    # Options for rebooting a compute node.
    #
    #
    class NodeRebootParameter

      include MsRestAzure

      # @return [ComputeNodeRebootOption] When to reboot the compute node and
      # what to do with currently running tasks. The default value is requeue.
      # Possible values include: 'requeue', 'terminate', 'taskCompletion',
      # 'retainedData'
      attr_accessor :node_reboot_option


      #
      # Mapper for NodeRebootParameter class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'NodeRebootParameter',
          type: {
            name: 'Composite',
            class_name: 'NodeRebootParameter',
            model_properties: {
              node_reboot_option: {
                client_side_validation: true,
                required: false,
                serialized_name: 'nodeRebootOption',
                type: {
                  name: 'Enum',
                  module: 'ComputeNodeRebootOption'
                }
              }
            }
          }
        }
      end
    end
  end
end
