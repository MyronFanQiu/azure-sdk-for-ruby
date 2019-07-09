# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_12_01_8_0
  module Models
    #
    # A range of task IDs that a task can depend on. All tasks with IDs in the
    # range must complete successfully before the dependent task can be
    # scheduled.

    # The start and end of the range are inclusive. For example, if a range has
    # start 9 and end 12, then it represents tasks '9', '10', '11' and '12'.
    #
    class TaskIdRange

      include MsRestAzure

      # @return [Integer] The first task ID in the range.
      attr_accessor :start

      # @return [Integer] The last task ID in the range.
      attr_accessor :end_property


      #
      # Mapper for TaskIdRange class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'TaskIdRange',
          type: {
            name: 'Composite',
            class_name: 'TaskIdRange',
            model_properties: {
              start: {
                client_side_validation: true,
                required: true,
                serialized_name: 'start',
                type: {
                  name: 'Number'
                }
              },
              end_property: {
                client_side_validation: true,
                required: true,
                serialized_name: 'end',
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