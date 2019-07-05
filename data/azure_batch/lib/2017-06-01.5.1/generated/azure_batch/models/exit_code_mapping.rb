# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_06_01_5_1
  module Models
    #
    # How the Batch service should respond if a task exits with a particular
    # exit code.
    #
    #
    class ExitCodeMapping

      include MsRestAzure

      # @return [Integer] A process exit code.
      attr_accessor :code

      # @return [ExitOptions] How the Batch service should respond if the task
      # exits with this exit code.
      attr_accessor :exit_options


      #
      # Mapper for ExitCodeMapping class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ExitCodeMapping',
          type: {
            name: 'Composite',
            class_name: 'ExitCodeMapping',
            model_properties: {
              code: {
                client_side_validation: true,
                required: true,
                serialized_name: 'code',
                type: {
                  name: 'Number'
                }
              },
              exit_options: {
                client_side_validation: true,
                required: true,
                serialized_name: 'exitOptions',
                type: {
                  name: 'Composite',
                  class_name: 'ExitOptions'
                }
              }
            }
          }
        }
      end
    end
  end
end
