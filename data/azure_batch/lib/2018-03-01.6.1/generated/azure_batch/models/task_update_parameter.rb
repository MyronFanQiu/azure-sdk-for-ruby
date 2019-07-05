# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_03_01_6_1
  module Models
    #
    # The set of changes to be made to a task.
    #
    #
    class TaskUpdateParameter

      include MsRestAzure

      # @return [TaskConstraints] Constraints that apply to this task. If
      # omitted, the task is given the default constraints. For multi-instance
      # tasks, updating the retention time applies only to the primary task and
      # not subtasks.
      attr_accessor :constraints


      #
      # Mapper for TaskUpdateParameter class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'TaskUpdateParameter',
          type: {
            name: 'Composite',
            class_name: 'TaskUpdateParameter',
            model_properties: {
              constraints: {
                client_side_validation: true,
                required: false,
                serialized_name: 'constraints',
                type: {
                  name: 'Composite',
                  class_name: 'TaskConstraints'
                }
              }
            }
          }
        }
      end
    end
  end
end
