# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # Options for reimaging a Compute Node.
    #
    #
    class NodeReimageParameter

      include MsRestAzure

      # @return [ComputeNodeReimageOption] When to reimage the Compute Node and
      # what to do with currently running Tasks. The default value is requeue.
      # Possible values include: 'requeue', 'terminate', 'taskCompletion',
      # 'retainedData'
      attr_accessor :node_reimage_option


      #
      # Mapper for NodeReimageParameter class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'NodeReimageParameter',
          type: {
            name: 'Composite',
            class_name: 'NodeReimageParameter',
            model_properties: {
              node_reimage_option: {
                client_side_validation: true,
                required: false,
                serialized_name: 'nodeReimageOption',
                type: {
                  name: 'Enum',
                  module: 'ComputeNodeReimageOption'
                }
              }
            }
          }
        }
      end
    end
  end
end
