# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  module Models
    #
    # A locality hint that can be used by the Batch service to select a compute
    # node on which to start a task.
    #
    #
    class AffinityInformation

      include MsRestAzure

      # @return [String] An opaque string representing the location of a
      # compute node or a task that has run previously. You can pass the
      # affinityId of a compute node to indicate that this task needs to run on
      # that compute node. Note that this is just a soft affinity. If the
      # target node is busy or unavailable at the time the task is scheduled,
      # then the task will be scheduled elsewhere.
      attr_accessor :affinity_id


      #
      # Mapper for AffinityInformation class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'AffinityInformation',
          type: {
            name: 'Composite',
            class_name: 'AffinityInformation',
            model_properties: {
              affinity_id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'affinityId',
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
