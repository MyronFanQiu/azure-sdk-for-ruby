# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_03_01_6_1
  module Models
    #
    # A range of exit codes and how the Batch service should respond to exit
    # codes within that range.
    #
    #
    class ExitCodeRangeMapping

      include MsRestAzure

      # @return [Integer] The first exit code in the range.
      attr_accessor :start

      # @return [Integer] The last exit code in the range.
      attr_accessor :end_property

      # @return [ExitOptions] How the Batch service should respond if the task
      # exits with an exit code in the range start to end (inclusive).
      attr_accessor :exit_options


      #
      # Mapper for ExitCodeRangeMapping class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ExitCodeRangeMapping',
          type: {
            name: 'Composite',
            class_name: 'ExitCodeRangeMapping',
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